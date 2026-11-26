using Microsoft.UI.Xaml;

namespace HajimiWinApp;

public partial class App : Application
{
    private const string SingleInstanceMutexName = @"Local\HajimiWinSingleInstanceMutex";
    private const string ActivateExistingEventName = @"Local\HajimiWinActivateExistingEvent";

    private Mutex? _instanceMutex;
    private EventWaitHandle? _activateEvent;
    private MainWindow? _mainWindow;

    public App()
    {
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _instanceMutex = new Mutex(initiallyOwned: true, SingleInstanceMutexName, out bool createdNew);
        if (!createdNew)
        {
            try
            {
                using var wakeEv = EventWaitHandle.OpenExisting(ActivateExistingEventName);
                wakeEv.Set();
            }
            catch
            {
                // Ignore if primary instance is still initializing
            }
            Environment.Exit(0);
            return;
        }

        _activateEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ActivateExistingEventName);
        _mainWindow = new MainWindow();

        _ = Task.Run(() =>
        {
            while (_activateEvent != null)
            {
                try
                {
                    if (_activateEvent.WaitOne())
                    {
                        _mainWindow.DispatcherQueue.TryEnqueue(() =>
                        {
                            _mainWindow.RestoreFromTray();
                        });
                    }
                }
                catch
                {
                    break;
                }
            }
        });

        if (!Environment.GetCommandLineArgs().Contains("--minimized", StringComparer.OrdinalIgnoreCase))
        {
            _mainWindow.Activate();
        }
    }
}
