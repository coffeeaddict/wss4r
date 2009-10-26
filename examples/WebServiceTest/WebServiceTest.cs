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


namespace WebServiceTest {
	class WebServiceTest {

		[MTAThread]
		static void Main1(string[] args) {
			WebServiceTest client = null;

			try {
				client = new WebServiceTest();
				client.Run();
			}
			catch (Exception ex) {
				Error(ex);
			}

			Console.WriteLine("Press [Enter] to continue...");
			Console.ReadLine();



//			//.......................................
//			
//			XmlDocument doc = new XmlDocument();
//			doc.Load("../../xml/wss4r-signed.xml");
//			XmlNodeList list = doc.GetElementsByTagName("Body", "http://schemas.xmlsoap.org/soap/envelope/");
//			//XmlNodeList list = doc.GetElementsByTagName("SignedInfo", "http://www.w3.org/2000/09/xmldsig#");
//			XmlDocument docPart = new XmlDocument();
//			docPart.LoadXml(list[0].OuterXml);
//
//			Microsoft.Web.Services2.Security.Xml.XmlDsigExcC14NTransform trans = new Microsoft.Web.Services2.Security.Xml.XmlDsigExcC14NTransform(false);
//			trans.Algorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
//			trans.LoadInput(docPart);
//			
//			Stream res = (Stream)trans.GetOutput(typeof(Stream));
//			Console.WriteLine( new StreamReader( res).ReadToEnd( ));
//
//			res.Seek(0,SeekOrigin.Begin);
//			Console.WriteLine(res.Length);
//			FileStream fs = File.Create("../../xml/out.xml");
//			string s = (new StreamReader(res).ReadToEnd());
//			byte[] outa = new ASCIIEncoding().GetBytes(s);
//			
//
//			fs.Write(outa, 0, outa.Length);
//			fs.Flush();
//			fs.Close();
//			res.Seek(0,SeekOrigin.Begin);
//			SHA1 sha1 = SHA1.Create();
//
//			byte[] hash = sha1.ComputeHash(res);
//			Console.WriteLine(Convert.ToBase64String(hash));
//
//			Console.ReadLine();
		}

		public void Run() {
			//WebServiceProxy.Service1 proxy = new WebServiceProxy.Service1();
			WebServiceProxy.Service1Wse proxy = new WebServiceProxy.Service1Wse();
			
			ISecurityTokenManager stm = SecurityTokenManager.GetSecurityTokenManagerByTokenType(WSTrust.TokenTypes.X509v3);
			X509SecurityTokenManager x509tm = stm as X509SecurityTokenManager;
			x509tm.DefaultSessionKeyAlgorithm = "TripleDES";

			//------Encryption
//			X509SecurityToken  token = getToken("server");
//			if (token == null)	throw new ApplicationException("Unable to obtain security token.");
//			EncryptedData ed = new EncryptedData(token);
//			proxy.RequestSoapContext.Security.Tokens.Add(token);
//			proxy.RequestSoapContext.Security.Elements.Add(ed);
			
			X509SecurityToken  token = getToken("client");
			if (token == null)	throw new ApplicationException("Unable to obtain security token.");
			proxy.RequestSoapContext.Security.Tokens.Add(token);
			proxy.RequestSoapContext.Security.Elements.Add(new MessageSignature(token));

			//------Username
//			string username      = Environment.UserName;
//			Console.Write("Passwort for '" + username + "': ");
//			string password = Console.ReadLine();
//			byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
//			//Array.Reverse(passwordBytes);
//
//			//string passwordEquivalent = Convert.ToBase64String( passwordBytes );
//			UsernameToken token = new UsernameToken( username, password, PasswordOption.SendHashed );
//			proxy.RequestSoapContext.Security.Tokens.Add(token);
//
//			//------Signature
//			proxy.RequestSoapContext.Security.Elements.Add( new MessageSignature( token ) );

			Console.WriteLine("Ausgabe: " + proxy.SayHello("test"));
		}

		private X509SecurityToken getToken(string which) {
			X509SecurityToken token = null;
			X509CertificateStore store = null;

			string serverKeyIdentifier = "bBwPfItvKp3b6TNDq+14qs58VJQ="; //"po3h4Y4J8ITs/pW3acuRjpT8V1o=";
			string clientKeyIdentifier = "gBfo0147lM6cKnTbbMSuMVvmFY4="; //"Gu4aD7+bYTVtmSveoPIWTRtzD3M=";

			store = X509CertificateStore.CurrentUserStore(X509CertificateStore.MyStore);
			store.OpenRead();
			X509CertificateCollection coll;

			if (which == "server") {
				coll = store.FindCertificateByKeyIdentifier(Convert.FromBase64String(serverKeyIdentifier));
			} else {
				coll = store.FindCertificateByKeyIdentifier(Convert.FromBase64String(clientKeyIdentifier));
			}
			
			if (coll.Count > 0) {
				X509Certificate cert = (X509Certificate) coll[0];
				token = new X509SecurityToken(cert);
				byte[] hash = cert.GetCertHash();
				string hashstring = cert.GetCertHashString();
				string serialstring = cert.GetSerialNumberString();
			}
			return token;
		}
		protected static void Error(Exception e) {
			Console.WriteLine("****** Exception Raised ******");
			StringBuilder sb = new StringBuilder();
			ProcessException(e, sb);
			Console.WriteLine(sb.ToString());
			Console.WriteLine("******************************");
		}
		private static void ProcessException(Exception e, StringBuilder sb) {
			if (e != null) {
				if (e is WebException) {
					// Process the Web Exception.
					WebException webExcep = e as WebException;
					if (webExcep.Response != null) {
						WebResponse response = webExcep.Response;
						string str = webExcep.Message;
						Stream responseStream = response.GetResponseStream();

						if ( responseStream.CanRead ) {
							StreamReader reader = new StreamReader(responseStream, System.Text.Encoding.UTF8);
							string excepStr = reader.ReadToEnd();
							sb.Append("Web Exception Occured: " + excepStr);
						}
						else {
							sb.Append("Web Exception Occured: " + e.ToString());
						}
					}
					else {
						sb.Append("Web Exception Occured: " + e.ToString());
					}
				}
				else {
					if (e is System.Web.Services.Protocols.SoapException) {
						System.Web.Services.Protocols.SoapException se = e as System.Web.Services.Protocols.SoapException;
						sb.Append("System.Web.Services.Protocols.SoapException:");
						sb.Append(Environment.NewLine);
						sb.Append("SOAP-Fault code: " + se.Code.ToString());
						sb.Append(Environment.NewLine);
						sb.Append("Message: ");
					}
					else {
						sb.Append(e.GetType().FullName);
						sb.Append(": ");
					}

					sb.Append(e.Message);

					if (e.InnerException != null) {
						sb.Append(" ---> ");
						ProcessException(e.InnerException, sb);
						sb.Append(Environment.NewLine);
						sb.Append("--- End of Inner Exception ---");
					}

					if (e.StackTrace != null) {
						sb.Append(Environment.NewLine);
						sb.Append(e.StackTrace);
					}
				}
			}
		}
	}
}
 
