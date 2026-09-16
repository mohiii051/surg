namespace SurgeApp;

public static class Brand
{
    // Keep display branding centralized so a future product-name change does not require
    // touching the authentication, account, or main-window logic.
    public const string ProductName = "SURGE";
    public const string ProductSubtitle = "FLIGHT TUNING SUITE";
    public const string WindowTitle = ProductName + " — Flight Tuning Suite";
    public const string AccountTitle = ProductName + " — Account";
}
