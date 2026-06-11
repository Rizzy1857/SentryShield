using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SentryUpdate
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Host.CreateDefaultBuilder(args)
                .UseWindowsService(options =>
                {
                    options.ServiceName = "SentryUpdate";
                })
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddHostedService<UpdateServer>();
                })
                .Build()
                .Run();
        }
    }
}
