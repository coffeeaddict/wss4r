using System;
using System.Collections;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Web;
using System.Web.Services;
using System.Security.Cryptography;
using Microsoft.Web.Services2;
using Microsoft.Web.Services2.Security;
using Microsoft.Web.Services2.Security.Tokens;
using Microsoft.Web.Services2.Security.X509;


namespace WebService
{
	/// <summary>
	/// Zusammenfassung für Service1.
	/// </summary>
	[WebService(Namespace="http://localhost/WebService/")]
	public class Service1 : System.Web.Services.WebService	{

		public Service1()
		{
			//CODEGEN: Dieser Aufruf ist für den ASP.NET-Webdienst-Designer erforderlich.
			InitializeComponent();
		}

		#region Vom Komponenten-Designer generierter Code
		
		//Erforderlich für den Webdienst-Designer 
		private IContainer components = null;
				
		/// <summary>
		/// Erforderliche Methode für die Designerunterstützung. 
		/// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
		/// </summary>
		private void InitializeComponent()
		{
		}

		/// <summary>
		/// Die verwendeten Ressourcen bereinigen.
		/// </summary>
		protected override void Dispose( bool disposing )
		{
			if(disposing && components != null)
			{
				components.Dispose();
			}
			base.Dispose(disposing);		
		}
		
		#endregion

		[WebMethod]
		public string HelloWorld()
		{
			return "Hello World";
		}
		[WebMethod]
		//[System.Web.Services.Protocols.SoapRpcMethod()]
		public string SayHello(string name) {
			SoapContext requestContext = Microsoft.Web.Services2.RequestSoapContext.Current;
			SoapContext responseContext = Microsoft.Web.Services2.ResponseSoapContext.Current;
			ISecurityTokenManager stm = SecurityTokenManager.GetSecurityTokenManagerByTokenType(WSTrust.TokenTypes.X509v3);
			X509SecurityTokenManager x509tm = stm as X509SecurityTokenManager;
			x509tm.DefaultSessionKeyAlgorithm = "TripleDES";

			//----------Encryption
			X509SecurityToken x509Token = getToken("client");
			if (x509Token == null) {
				//throw new SecurityFault(SecurityFault.FailedAuthenticationMessage, SecurityFault.FailedAuthenticationCode);
				throw new SecurityFault("Could not get encryption token...", SecurityFault.FailedAuthenticationCode);
			} else {
				EncryptedData ed = new EncryptedData(x509Token);
				responseContext.Security.Tokens.Add(x509Token);
				responseContext.Security.Elements.Add(ed);
			}

			//---------UsernameToken
//			UsernameToken usernameToken = GetSigningToken() as UsernameToken;
//			if (usernameToken == null || usernameToken.PasswordOption == PasswordOption.SendPlainText) {
//				throw new SecurityFault(SecurityFault.FailedAuthenticationMessage, SecurityFault.FailedAuthenticationCode);
//			}
//			
			//---------Signature
//			//X509SecurityToken 	
			x509Token = getToken("server");
			X509SecurityToken x509TokenSigningToken = GetSigningToken() as X509SecurityToken;
			if (x509TokenSigningToken == null) { //|| !CompareArray(x509TokenSigningToken.KeyIdentifier.Value, Convert.FromBase64String(clientKeyIdentifier))) {
				throw new SecurityFault("Could not get signing token...", SecurityFault.FailedAuthenticationCode);
			} else {
				responseContext.Security.Tokens.Add(x509Token);
				responseContext.Security.Elements.Add(new MessageSignature(x509Token));
			}

			return "Hello," + name;
		}

		public SecurityToken GetSigningToken() {
			SoapContext context = RequestSoapContext.Current;
			foreach ( ISecurityElement element in context.Security.Elements ) {
				if ( element is MessageSignature ) {
					// The given context contains a Signature element.
					MessageSignature sig = element as MessageSignature;
					return sig.SigningToken;
					//if (CheckSignature(context, sig)) {
					//	return sig.SigningToken;
					//}
				}
			}
			return null;
		}
		private bool CheckSignature(SoapContext context, MessageSignature signature) {
			//
			// Now verify which parts of the message were actually signed.
			//
			SignatureOptions actualOptions   = signature.SignatureOptions;
			SignatureOptions expectedOptions = SignatureOptions.IncludeSoapBody;
          
			if (context.Security != null && context.Security.Timestamp != null ) 
				expectedOptions |= SignatureOptions.IncludeTimestamp;
            
			//
			// The <Action> and <To> are required addressing elements.
			//
			expectedOptions |= SignatureOptions.IncludeAction;
			expectedOptions |= SignatureOptions.IncludeTo;

			if ( context.Addressing.FaultTo != null && context.Addressing.FaultTo.TargetElement != null )
				expectedOptions |= SignatureOptions.IncludeFaultTo;

			if ( context.Addressing.From != null && context.Addressing.From.TargetElement != null )
				expectedOptions |= SignatureOptions.IncludeFrom;

			if ( context.Addressing.MessageID != null && context.Addressing.MessageID.TargetElement != null )
				expectedOptions |= SignatureOptions.IncludeMessageId;

			if ( context.Addressing.RelatesTo != null && context.Addressing.RelatesTo.TargetElement != null )
				expectedOptions |= SignatureOptions.IncludeRelatesTo;

			if ( context.Addressing.ReplyTo != null && context.Addressing.ReplyTo.TargetElement != null )
				expectedOptions |= SignatureOptions.IncludeReplyTo;
			//
			// Check if the all the expected options are the present.
			//
			return ( ( expectedOptions & actualOptions ) == expectedOptions );
                
		}
		private X509SecurityToken getToken(string which) {
			X509SecurityToken token = null;
			X509CertificateStore store = null;

			string serverKeyIdentifier = "bBwPfItvKp3b6TNDq+14qs58VJQ="; //"po3h4Y4J8ITs/pW3acuRjpT8V1o=";
			string clientKeyIdentifier = "gBfo0147lM6cKnTbbMSuMVvmFY4="; //"Gu4aD7+bYTVtmSveoPIWTRtzD3M=";

			//string serverKeyIdentifier = "po3h4Y4J8ITs/pW3acuRjpT8V1o=";
			//string clientKeyIdentifier = "Gu4aD7+bYTVtmSveoPIWTRtzD3M=";

			store = X509CertificateStore.LocalMachineStore(X509CertificateStore.MyStore);
			store.OpenRead();
			X509CertificateCollection coll;

			if (which == "server") {
				coll = store.FindCertificateByKeyIdentifier(Convert.FromBase64String(serverKeyIdentifier));
			} else {
				coll = store.FindCertificateByKeyIdentifier(Convert.FromBase64String(clientKeyIdentifier));
			}
			
			if (coll.Count > 0) {
				X509Certificate cert = (X509Certificate) coll[0];
				RSA rsa = cert.Key;
				token = new X509SecurityToken(cert);
			}
			return token;
		}
		public bool CompareArray(byte[] a, byte[] b) {
			if (a != null && b != null && a.Length == b.Length) {
				int index = a.Length;
				while (--index > -1)
					if (a[index] != b[index])
						return false;
				return true;
			}
			else if (a == null && b == null)
				return true;
			else
				return false;
		}
	}
}
