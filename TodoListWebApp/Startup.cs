using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(TodoListWebApp.Startup))]

namespace TodoListWebApp
{
	public partial class Startup
	{
		// ReSharper disable once UnusedMember.Global
		public void Configuration(IAppBuilder app)
		{
			ConfigureAuth(app);
		}
	}
}