using System;

using Microsoft.Web.Services2.Security;
using Microsoft.Web.Services2.Security.Tokens;
using Microsoft.Web.Services2.Security.X509;
using System.Text;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Security;
using System.Xml;
using System.Xml.XPath;

using System.Collections;
using System.Configuration;
using System.Net;
using System.IO;
using System.Web.Services.Protocols;

namespace RailsTest {
	class RailsTest {

		[MTAThread]
		static void Main(string[] args) {
			RailsTest client = null;

			try {
				client = new RailsTest();
				client.Run();
			}
			catch (Exception ex) {
				Console.WriteLine(ex);
			}

			Console.WriteLine("Press [Enter] to continue...");
			Console.ReadLine();
		}

		public void Run() {
			WebServiceTest.railsservice.SimpleServiceServiceWse proxy = new WebServiceTest.railsservice.SimpleServiceServiceWse();

			//------Username
			string username="Ron";
			string password = "noR";

			byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
			Array.Reverse(passwordBytes);
			
			string passwordEquivalent = Convert.ToBase64String( passwordBytes );
			UsernameToken token = new UsernameToken( username, password, PasswordOption.SendHashed );
			proxy.RequestSoapContext.Security.Tokens.Add(token);
			
			Console.WriteLine("Ausgabe: " + proxy.test("test"));
		}
	}
}
 
