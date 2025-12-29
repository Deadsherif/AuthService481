using AuthService.MVVM.View;
using AuthService.Services;
using System;
using static AuthService.Services.SubscriptionService;

namespace AuthService
{

    public class Auth 
    {
        public static SubscriptionService.SubscriptionStatus ValidateAuth(string addinName, string addinID)
        {
            if (LocalAuthCache.TryGetValidEntry(addinName, addinID).ConfigureAwait(false).GetAwaiter().GetResult())
            {
                SubscriptionService.Status = SubscriptionService.SubscriptionStatus.Valid;
                return SubscriptionStatus.Valid;
            }
            SubscriptionService.Status = SubscriptionService.SubscriptionStatus.NotFound;
            AuthWindow window = new AuthWindow(addinName, addinID);
            window.ShowDialog();
            return SubscriptionService.Status;

        }
    }
}
