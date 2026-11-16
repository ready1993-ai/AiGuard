// VPNGuard P03: сетевые пробы внешнего адреса с известным маршрутом.
// Маршруты: system (как у приложений: системный прокси или напрямую), direct,
// http://host:port (HTTP CONNECT), socks5://host:port. Семейства: v4, v6, any.
// Каждый результат хранит источник, маршрут, время начала/конца и длительность.
// C# 5 (компилятор Windows PowerShell 5.1).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

public class VGProbeResult
{
    public string Source;
    public string Route;      // что запрошено
    public string RouteUsed;  // чем реально шли
    public string Family;
    public string Status;     // ok | invalid | error | timeout | unavailable
    public string Value;
    public string Error;
    public DateTime StartedUtc;
    public DateTime FinishedUtc;
    public long ElapsedMs;
}

public class VGProbeUnavailable : Exception
{
    public VGProbeUnavailable(string m) : base(m) { }
}

public static class VGProbe
{
    // Только для тестов: считать, что глобального IPv6 на компьютере нет.
    public static bool ForceNoIPv6 = false;

    public static Task<VGProbeResult> Start(string url, string route, string family, int timeoutMs)
    {
        return Task.Run(() => Run(url, route, family, timeoutMs));
    }

    public static bool HasGlobalIPv6()
    {
        if (ForceNoIPv6) return false;
        foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            foreach (UnicastIPAddressInformation ua in ni.GetIPProperties().UnicastAddresses)
            {
                IPAddress a = ua.Address;
                if (a.AddressFamily != AddressFamily.InterNetworkV6) continue;
                if (a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Teredo || IPAddress.IsLoopback(a)) continue;
                byte b0 = a.GetAddressBytes()[0];
                if ((b0 & 0xE0) == 0x20) return true; // 2000::/3 - глобальные
            }
        }
        return false;
    }

    // Какой маршрут реально будет использован для URL.
    public static string ResolveRoute(Uri uri, string route)
    {
        if (string.IsNullOrEmpty(route) || route == "system")
        {
            IWebProxy p = WebRequest.GetSystemWebProxy();
            if (p == null || p.IsBypassed(uri)) return "direct";
            Uri pu = p.GetProxy(uri);
            if (pu == null || pu == uri || pu.Authority == uri.Authority) return "direct";
            return "http://" + pu.Authority;
        }
        if (route == "direct") return route;
        if (Regex.IsMatch(route, @"^(http|socks5)://[^/\s:]+:\d{1,5}/?$", RegexOptions.IgnoreCase)) return route.TrimEnd('/').ToLowerInvariant();
        throw new ArgumentException("Неизвестный маршрут: " + route);
    }

    public static VGProbeResult Run(string url, string route, string family, int timeoutMs)
    {
        VGProbeResult r = new VGProbeResult();
        r.Source = url; r.Route = route; r.Family = family; r.StartedUtc = DateTime.UtcNow;
        Stopwatch sw = Stopwatch.StartNew();
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        try
        {
            Uri uri = new Uri(url);
            r.RouteUsed = ResolveRoute(uri, route);
            string body = Fetch(uri, r.RouteUsed, family, deadline);
            string ip = ExtractIp(body, family);
            if (ip == null) { r.Status = "invalid"; r.Error = "ответ не содержит IP нужного семейства"; r.Value = Trunc(body); }
            else { r.Status = "ok"; r.Value = ip; }
        }
        catch (VGProbeUnavailable ex) { r.Status = "unavailable"; r.Error = ex.Message; }
        catch (TimeoutException) { r.Status = "timeout"; r.Error = "таймаут " + timeoutMs + " мс"; }
        catch (Exception ex)
        {
            if (DateTime.UtcNow >= deadline.AddMilliseconds(-50)) { r.Status = "timeout"; r.Error = "таймаут " + timeoutMs + " мс"; }
            else { r.Status = "error"; r.Error = ex.GetBaseException().Message; }
        }
        sw.Stop();
        r.FinishedUtc = DateTime.UtcNow;
        r.ElapsedMs = sw.ElapsedMilliseconds;
        return r;
    }

    static int Remaining(DateTime deadline)
    {
        int ms = (int)(deadline - DateTime.UtcNow).TotalMilliseconds;
        if (ms <= 0) throw new TimeoutException();
        return ms;
    }

    static TcpClient ConnectTo(IPAddress addr, int port, DateTime deadline)
    {
        TcpClient tcp = new TcpClient(addr.AddressFamily);
        Task t = tcp.ConnectAsync(addr, port);
        bool done;
        try { done = t.Wait(Remaining(deadline)); }
        catch (AggregateException ex) { tcp.Close(); throw ex.GetBaseException(); }
        if (!done) { tcp.Close(); throw new TimeoutException(); }
        return tcp;
    }

    static IPAddress[] Resolve(string host, DateTime deadline)
    {
        IPAddress literal;
        if (IPAddress.TryParse(host, out literal)) return new IPAddress[] { literal };
        Task<IPAddress[]> t = Dns.GetHostAddressesAsync(host);
        bool done;
        try { done = t.Wait(Remaining(deadline)); }
        catch (AggregateException ex) { throw ex.GetBaseException(); }
        if (!done) throw new TimeoutException();
        return t.Result;
    }

    static TcpClient ConnectHost(string host, int port, string family, DateTime deadline)
    {
        IPAddress lit;
        bool loopLiteral = IPAddress.TryParse(host, out lit) && IPAddress.IsLoopback(lit);
        // Без глобального IPv6 Windows часто не отдаёт AAAA-записи - это «недоступно», а не ошибка.
        if (family == "v6" && !loopLiteral && !HasGlobalIPv6())
            throw new VGProbeUnavailable("нет глобального IPv6-адреса на компьютере");
        IPAddress[] all = Resolve(host, deadline);
        Exception last = null;
        bool v6 = family == "v6", v4 = family == "v4";
        int matched = 0;
        foreach (IPAddress a in all)
        {
            if (v4 && a.AddressFamily != AddressFamily.InterNetwork) continue;
            if (v6 && a.AddressFamily != AddressFamily.InterNetworkV6) continue;
            matched++;
            if (a.AddressFamily == AddressFamily.InterNetworkV6 && !IPAddress.IsLoopback(a) && !HasGlobalIPv6())
                throw new VGProbeUnavailable("нет глобального IPv6-адреса на компьютере");
            try { return ConnectTo(a, port, deadline); }
            catch (TimeoutException) { throw; }
            catch (Exception ex) { last = ex; }
        }
        if (matched == 0)
        {
            if (v6 && !HasGlobalIPv6()) throw new VGProbeUnavailable("нет глобального IPv6-адреса на компьютере");
            throw new Exception("у " + host + " нет адресов " + (v6 ? "IPv6" : v4 ? "IPv4" : ""));
        }
        throw last;
    }

    static void SetTimeouts(TcpClient tcp, DateTime deadline)
    {
        int ms = Remaining(deadline);
        tcp.ReceiveTimeout = ms; tcp.SendTimeout = ms;
    }

    static void WriteAll(Stream s, byte[] b) { s.Write(b, 0, b.Length); s.Flush(); }

    static void ReadExact(Stream s, byte[] buf, int count, TcpClient tcp, DateTime deadline)
    {
        int got = 0;
        while (got < count)
        {
            SetTimeouts(tcp, deadline);
            int n = s.Read(buf, got, count - got);
            if (n <= 0) throw new IOException("соединение закрыто прокси");
            got += n;
        }
    }

    static string ReadHeaderBlock(Stream s, TcpClient tcp, DateTime deadline)
    {
        StringBuilder sb = new StringBuilder();
        byte[] one = new byte[1];
        while (sb.Length < 16384)
        {
            SetTimeouts(tcp, deadline);
            int n = s.Read(one, 0, 1);
            if (n <= 0) throw new IOException("соединение закрыто до конца заголовков");
            sb.Append((char)one[0]);
            if (sb.Length >= 4 && sb[sb.Length - 1] == '\n' && sb[sb.Length - 2] == '\r' && sb[sb.Length - 3] == '\n' && sb[sb.Length - 4] == '\r') break;
        }
        return sb.ToString();
    }

    static string Fetch(Uri uri, string used, string family, DateTime deadline)
    {
        string host = uri.DnsSafeHost;
        int port = uri.Port;
        string hostHeader = uri.IsDefaultPort ? uri.Host : uri.Host + ":" + port;
        TcpClient tcp = null;
        try
        {
            if (used == "direct")
            {
                tcp = ConnectHost(host, port, family, deadline);
            }
            else
            {
                Uri p = new Uri(used);
                tcp = ConnectHost(p.DnsSafeHost, p.Port, "any", deadline);
            }
            SetTimeouts(tcp, deadline);
            Stream s = tcp.GetStream();
            if (used.StartsWith("http://"))
            {
                IPAddress hostIp; string th = IPAddress.TryParse(host, out hostIp) ? hostIp.ToString() : host;
                string target = (th.Contains(":") ? "[" + th + "]" : th) + ":" + port;
                WriteAll(s, Encoding.ASCII.GetBytes("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"));
                string head = ReadHeaderBlock(s, tcp, deadline);
                string status = head.Split('\n')[0].Trim();
                if (!Regex.IsMatch(status, @"^HTTP/1\.[01] 200")) throw new Exception("HTTP-прокси отказал: " + status);
            }
            else if (used.StartsWith("socks5://"))
            {
                WriteAll(s, new byte[] { 5, 1, 0 });
                byte[] hello = new byte[2];
                ReadExact(s, hello, 2, tcp, deadline);
                if (hello[0] != 5 || hello[1] != 0) throw new Exception("SOCKS5: прокси требует неподдерживаемую авторизацию");
                IPAddress sip; string sh = IPAddress.TryParse(host, out sip) ? sip.ToString() : host;
                byte[] hb = Encoding.ASCII.GetBytes(sh);
                if (hb.Length > 255) throw new Exception("SOCKS5: слишком длинное имя хоста");
                byte[] req = new byte[7 + hb.Length];
                req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3; req[4] = (byte)hb.Length;
                Buffer.BlockCopy(hb, 0, req, 5, hb.Length);
                req[5 + hb.Length] = (byte)(port >> 8); req[6 + hb.Length] = (byte)(port & 0xFF);
                WriteAll(s, req);
                byte[] rep = new byte[4];
                ReadExact(s, rep, 4, tcp, deadline);
                if (rep[1] != 0) throw new Exception("SOCKS5: отказ, код " + rep[1]);
                int skip = rep[3] == 1 ? 4 : rep[3] == 4 ? 16 : -1;
                if (skip < 0) { byte[] len = new byte[1]; ReadExact(s, len, 1, tcp, deadline); skip = len[0]; }
                byte[] rest = new byte[skip + 2];
                ReadExact(s, rest, rest.Length, tcp, deadline);
            }
            if (uri.Scheme == "https")
            {
                SslStream ssl = new SslStream(s, false);
                SetTimeouts(tcp, deadline);
                ssl.AuthenticateAsClient(uri.Host, null, SslProtocols.Tls12, true);
                s = ssl;
            }
            string get = "GET " + uri.PathAndQuery + " HTTP/1.1\r\nHost: " + hostHeader +
                         "\r\nUser-Agent: VPNGuard\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            WriteAll(s, Encoding.ASCII.GetBytes(get));
            string headers = ReadHeaderBlock(s, tcp, deadline);
            string statusLine = headers.Split('\n')[0].Trim();
            Match m = Regex.Match(statusLine, @"^HTTP/1\.[01] (\d{3})");
            if (!m.Success) throw new Exception("некорректный ответ: " + Trunc(statusLine));
            if (m.Groups[1].Value != "200") throw new Exception("HTTP " + m.Groups[1].Value);
            bool chunked = Regex.IsMatch(headers, @"(?im)^transfer-encoding:\s*chunked");
            Match cl = Regex.Match(headers, @"(?im)^content-length:\s*(\d+)");
            int limit = cl.Success ? Math.Min(int.Parse(cl.Groups[1].Value), 65536) : 65536;
            MemoryStream body = new MemoryStream();
            byte[] buf = new byte[4096];
            while (body.Length < limit)
            {
                SetTimeouts(tcp, deadline);
                int want = (int)Math.Min(buf.Length, limit - body.Length);
                int n = s.Read(buf, 0, want);
                if (n <= 0) break;
                body.Write(buf, 0, n);
            }
            string text = Encoding.UTF8.GetString(body.ToArray());
            if (chunked) text = Dechunk(text);
            return text;
        }
        finally { if (tcp != null) tcp.Close(); }
    }

    static string Dechunk(string raw)
    {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < raw.Length)
        {
            int eol = raw.IndexOf("\r\n", i, StringComparison.Ordinal);
            if (eol < 0) break;
            int size;
            string hex = raw.Substring(i, eol - i).Split(';')[0].Trim();
            if (!int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out size) || size == 0) break;
            int start = eol + 2;
            if (start + size > raw.Length) { sb.Append(raw.Substring(start)); break; }
            sb.Append(raw.Substring(start, size));
            i = start + size + 2;
        }
        return sb.ToString();
    }

    public static string ExtractIp(string body, string family)
    {
        if (body == null) return null;
        string t = body.Trim();
        // Cloudflare /cdn-cgi/trace: строки key=value, нужен ip=
        Match tr = Regex.Match(t, @"(?m)^ip=(\S+)\s*$");
        if (tr.Success) t = tr.Groups[1].Value;
        Match j = Regex.Match(t, "\"ip\"\\s*:\\s*\"([^\"]+)\"");
        if (j.Success) t = j.Groups[1].Value.Trim();
        IPAddress a;
        // .NET принимает "1" как 0.0.0.1: IPv4 только в виде четырёх чисел
        bool dotted = Regex.IsMatch(t, @"^\d{1,3}(\.\d{1,3}){3}$");
        if (!dotted && !t.Contains(":")) return null;
        if (!IPAddress.TryParse(t, out a)) return null;
        if (family == "v4" && a.AddressFamily != AddressFamily.InterNetwork) return null;
        if (family == "v6" && a.AddressFamily != AddressFamily.InterNetworkV6) return null;
        return a.ToString();
    }

    // ---- DNS через системный резолвер Windows, в обход кэша (P04) ----
    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode, EntryPoint = "DnsQuery_W")]
    static extern int DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);
    [DllImport("dnsapi.dll")]
    static extern void DnsRecordListFree(IntPtr list, int freeType);

    // type 1 = A (адреса IPv4), 16 = TXT. Возвращает строки ответа.
    public static string[] DnsLookup(string name, int type)
    {
        IntPtr res;
        int rc = DnsQuery(name, (ushort)type, 0x8 /* DNS_QUERY_BYPASS_CACHE */, IntPtr.Zero, out res, IntPtr.Zero);
        if (rc != 0) throw new Exception("DNS-запрос " + name + ": код " + rc);
        List<string> list = new List<string>();
        try
        {
            int ptr = IntPtr.Size;
            int dataOff = ptr * 2 + 16; // pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved
            for (IntPtr r = res; r != IntPtr.Zero; r = Marshal.ReadIntPtr(r))
            {
                int rtype = (ushort)Marshal.ReadInt16(r, ptr * 2);
                if (rtype != type) continue;
                if (type == 1)
                {
                    list.Add(Marshal.ReadByte(r, dataOff) + "." + Marshal.ReadByte(r, dataOff + 1) + "." + Marshal.ReadByte(r, dataOff + 2) + "." + Marshal.ReadByte(r, dataOff + 3));
                }
                else if (type == 16)
                {
                    int count = Marshal.ReadInt32(r, dataOff);
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr s = Marshal.ReadIntPtr(r, dataOff + ptr + i * ptr);
                        if (s != IntPtr.Zero) list.Add(Marshal.PtrToStringUni(s));
                    }
                }
            }
        }
        finally { DnsRecordListFree(res, 1); }
        return list.ToArray();
    }

    public static Task<string[]> DnsAsync(string name, int type)
    {
        return Task.Run(() => DnsLookup(name, type));
    }

    static string Trunc(string s)
    {
        if (s == null) return "";
        s = s.Replace("\r", " ").Replace("\n", " ").Trim();
        return s.Length > 60 ? s.Substring(0, 60) + "…" : s;
    }
}
