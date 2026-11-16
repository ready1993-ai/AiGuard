using System;
using System.Net.NetworkInformation;
using System.Threading;
using Microsoft.Win32;

public static class VPNGuardNetworkMonitor
{
    private static int changed;
    private static bool started;

    public static void Start()
    {
        if (started) return;
        NetworkChange.NetworkAddressChanged += AddressChanged;
        NetworkChange.NetworkAvailabilityChanged += AvailabilityChanged;
        SystemEvents.PowerModeChanged += PowerChanged;
        started = true;
    }

    private static void AddressChanged(object sender, EventArgs args)
    {
        Interlocked.Exchange(ref changed, 1);
    }

    private static void AvailabilityChanged(object sender, NetworkAvailabilityEventArgs args)
    {
        Interlocked.Exchange(ref changed, 1);
    }

    private static void PowerChanged(object sender, PowerModeChangedEventArgs args)
    {
        Interlocked.Exchange(ref changed, 1);
    }

    // Внешний сигнал перепроверки (пропуск таймера после сна или зависания).
    public static void Signal()
    {
        Interlocked.Exchange(ref changed, 1);
    }

    public static bool ConsumeChange()
    {
        return Interlocked.Exchange(ref changed, 0) != 0;
    }

    public static void Stop()
    {
        if (!started) return;
        NetworkChange.NetworkAddressChanged -= AddressChanged;
        NetworkChange.NetworkAvailabilityChanged -= AvailabilityChanged;
        SystemEvents.PowerModeChanged -= PowerChanged;
        started = false;
    }
}
