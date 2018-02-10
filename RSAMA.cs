
using System;
using System.IO;
using System.Xml;
using System.Text;
using System.Collections.Specialized;
using Microsoft.MetadirectoryServices;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data.SqlClient;
using System.Data;
using com.rsa.admin;
using System.Security;
using System.Runtime.InteropServices;
using com.rsa.admin.data;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using com.rsa.command;
using com.rsa.common.search;
using com.rsa.authmgr.admin.principalmgt.data;
using com.rsa.authmgr.admin.principalmgt;
using com.rsa.authmgr.admin.tokenmgt;
using com.rsa.authmgr.admin.tokenmgt.data;
using com.rsa.common;
using System.Linq;
using Ionic.Zip;

namespace FimSync_Ezma
{
    internal class UserNotFoundException : Exception
    {
        public UserNotFoundException()
            : base() { }
    }

    internal class RSAAccount
    {
        private PrincipalDTO m_Principal;
        private ListTokenDTO[] m_Tokens;

        internal PrincipalDTO Principal
        {
            get { return m_Principal; }
        }
        
        internal ListTokenDTO[] Tokens
        {
            get { return m_Tokens; }
        }


        internal RSAAccount(PrincipalDTO principal, ListTokenDTO[] tokens)
        {
            m_Principal = principal;
            m_Tokens = tokens;
        }
 

    }


    public class EzmaExtension :
    IMAExtensible2CallExport,
    IMAExtensible2CallImport,
     IMAExtensible2GetSchema,
     IMAExtensible2GetCapabilities,
     IMAExtensible2GetParameters
    {

        private int m_importDefaultPageSize = 50;
        private int m_importMaxPageSize = 50;
        private int m_exportDefaultPageSize = 10;
        private int m_exportMaxPageSize = 20;

        #region class members
        private SOAPCommandTarget m_Connection = null;
        private SecurityDomainDTO m_SecurityDomain = null;
        private IdentitySourceDTO m_IdentitySource = null;
        #endregion

        #region Configuration

        private string m_RSAServer;
        private string m_AdministrativeUserName;
        private string m_AdministrativePassword;
        private string m_CommandClientUserName;
        private string m_CommandClientPassword;
        private string m_RSARealm;
        private string m_DefaultShell;
        private string m_SMTPHost;
        private string m_Sender;
        private string m_ErrorsMail;
        private string m_OtherTokenReceivers;
        private string m_IdentitySourceName;
        private string m_TokenFilePath;
        #endregion


        #region RSA Attributes(Schema)
        private string firstName = "First Name";
        private string lastName = "Last Name";
        private string middleName = "Middle Name";
        private string userID = "User ID";
        private string managerEmailAddress = "Manager Email Address";
        private string identitySource = "Identity Source";
        private string securityDomain = "Security Domain";
        private string lockoutStatus = "Lockout Status";
        private List<string> tokenSerialNumber = new List<string>();
        private List<string> tokenGuid = new List<string>();
        #endregion

        public EzmaExtension()
        {
        }

        public MACapabilities Capabilities
        {
            get
            {
                MACapabilities myCapabilities = new MACapabilities();

                myCapabilities.ConcurrentOperation = true;
                myCapabilities.ObjectRename = false;
                myCapabilities.DeleteAddAsReplace = true;
                myCapabilities.DeltaImport = false;
                myCapabilities.DistinguishedNameStyle = MADistinguishedNameStyle.None;
                myCapabilities.ExportType = MAExportType.AttributeUpdate;
                myCapabilities.NoReferenceValuesInFirstExport = false;
                myCapabilities.Normalizations = MANormalizations.None;

                return myCapabilities;
            }
        }

        public IList<ConfigParameterDefinition> GetConfigParameters(KeyedCollection<string, ConfigParameter> configParameters, ConfigParameterPage page)
        {
            List<ConfigParameterDefinition> configParametersDefinitions = new List<ConfigParameterDefinition>();

            switch (page)
            {
                case ConfigParameterPage.Connectivity:

                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("RSA Server", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Administrative User Name", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateEncryptedStringParameter("Administrative Password", string.Empty));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Command Client User Name", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateEncryptedStringParameter("Command Client Password", string.Empty));

                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("RSA Realm", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Default Shell", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Identity Source", ""));

                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Other Token Receivers", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Sender", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Errors Mail", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("SMTP Host", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Token File Path", ""));

                    break;

                case ConfigParameterPage.Global:
                    break;

                case ConfigParameterPage.Partition:
                    break;

                case ConfigParameterPage.RunStep:
                    break;
            }

            return configParametersDefinitions;
        }

        public ParameterValidationResult ValidateConfigParameters(KeyedCollection<string, ConfigParameter> configParameters, ConfigParameterPage page)
        {
            ParameterValidationResult myResults = new ParameterValidationResult();
            return myResults;
        }

        public Schema GetSchema(KeyedCollection<string, ConfigParameter> configParameters)
        {

            Microsoft.MetadirectoryServices.SchemaType personType = Microsoft.MetadirectoryServices.SchemaType.Create("Person", false);

            this.GetMAConfig(configParameters);


            string[] rsaAttributes = new string[10];
            rsaAttributes[0] = "First Name";
            rsaAttributes[1] = "Last Name";
            rsaAttributes[2] = "Middle Name";
            rsaAttributes[3] = "User ID";
            rsaAttributes[4] = "Manager Email Address";
            rsaAttributes[5] = "Identity Source";
            rsaAttributes[6] = "Security Domain";
            rsaAttributes[7] = "Lockout Status";
            rsaAttributes[8] = "Token Serial Number";
            rsaAttributes[9] = "Token GUID";


            foreach(string attribName in rsaAttributes)
            {
                if (attribName == "User ID")
                {
                    personType.Attributes.Add(SchemaAttribute.CreateAnchorAttribute(attribName, AttributeType.String));
                }
                
                else if ( attribName == "Token Serial Number" || attribName == "Token GUID")
                {
                    personType.Attributes.Add(SchemaAttribute.CreateMultiValuedAttribute(attribName, AttributeType.String));
                }

                else
                {
                    personType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute(attribName, AttributeType.String));
                }
            }

            Schema schema = Schema.Create();
            schema.Types.Add(personType);

            return schema;
        }

     
        private int m_importPageSize;
        private List<RSAAccount> rsaResult;
        int userToRead = 0;

        public OpenImportConnectionResults OpenImportConnection(KeyedCollection<string, ConfigParameter> configParameters, Schema types, OpenImportConnectionRunStep importRunStep)
        {
            try
            {
                this.GetMAConfig(configParameters);

                this.OpenRSAConnection();

                m_importPageSize = importRunStep.PageSize;

                rsaResult = this.ImportUsers();

                return new OpenImportConnectionResults();
            }
            catch (Exception ex)
            {
                EmailError(ex);
                throw ex;
            }

        }

        private void GetMAConfig(KeyedCollection<string, ConfigParameter> configParameters)
        {
            m_RSAServer = configParameters["RSA Server"].Value + "//ims-ws/services/CommandServer";
            m_AdministrativeUserName = configParameters["Administrative User Name"].Value;
            m_AdministrativePassword = SecureStringToString(configParameters["Administrative Password"].SecureValue);
            m_CommandClientUserName = configParameters["Command Client User Name"].Value;
            m_CommandClientPassword = SecureStringToString(configParameters["Command Client Password"].SecureValue);

            m_RSARealm = configParameters["RSA Realm"].Value;
            m_DefaultShell = configParameters["Default Shell"].Value;
            m_IdentitySourceName = configParameters["Identity Source"].Value;

            m_OtherTokenReceivers = configParameters["Other Token Receivers"].Value;
            m_Sender = configParameters["Sender"].Value;
            m_ErrorsMail = configParameters["Errors Mail"].Value;
            m_SMTPHost = configParameters["SMTP Host"].Value;
            m_TokenFilePath = configParameters["Token File Path"].Value;
        }

        public GetImportEntriesResults GetImportEntries(GetImportEntriesRunStep importRunStep)
        {
            try
            {

                GetImportEntriesResults importReturnInfo;
                List<CSEntryChange> csentries = new List<CSEntryChange>();

                while (userToRead < rsaResult.Count && csentries.Count < m_importPageSize)
                {
                    RSAAccount rsaAccount = rsaResult[userToRead];
                    PrincipalDTO principal = rsaAccount.Principal;
                    firstName = principal.firstName;
                    lastName = principal.lastName;
                    middleName = principal.middleName;
                    userID = principal.userID;
                    managerEmailAddress = principal.email;
                    identitySource = principal.identitySourceGuid;
                    securityDomain = principal.securityDomainGuid;
                    lockoutStatus = principal.lockoutStatus.ToString();

                    tokenSerialNumber = new List<string>();
                    tokenGuid = new List<string>();

                    foreach (ListTokenDTO token in rsaAccount.Tokens)
                    {
                        tokenSerialNumber.Add(token.serialNumber);
                        tokenGuid.Add(token.guid);
                    }

                    CSEntryChange csentry1 = CSEntryChange.Create();

                    csentry1.ObjectModificationType = ObjectModificationType.Add;
                    csentry1.ObjectType = "Person";

                    if (firstName != null)
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("First Name", firstName));

                    if (lastName != null)
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("Last Name", lastName));

                    if (middleName != null)
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("Middle Name", middleName));

                    csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("User ID", userID));

                    if (managerEmailAddress != null)
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("Manager Email Address", managerEmailAddress));

                    csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("Identity Source", identitySource));
                    csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("Security Domain", securityDomain));
                    csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("Lockout Status", lockoutStatus));


                    IList<object> serials = (IList<object>)tokenSerialNumber.Select(x => (object)x).ToList();
                    IList<object> guids = (IList<object>)tokenGuid.Select(x => (object)x).ToList();

                    csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("Token Serial Number", serials));
                    csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("Token GUID", guids));


                    csentries.Add(csentry1);

                    userToRead++;
                }

                importReturnInfo = new GetImportEntriesResults();

                importReturnInfo.MoreToImport = (userToRead < rsaResult.Count) ;
             

                importReturnInfo.CSEntries = csentries;
                return importReturnInfo;
            }
            catch (Exception ex) 
            {
                EmailError(ex);
                throw ex;
            }
        }

        public CloseImportConnectionResults CloseImportConnection(CloseImportConnectionRunStep importRunStepInfo)
        {
            try
            {
                this.CloseRSAConnection();

                return new CloseImportConnectionResults();
            }
            catch (Exception ex)
            {
                EmailError(ex);
                throw ex;
            }
        }

        public void OpenExportConnection(KeyedCollection<string, ConfigParameter> configParameters, Schema types, OpenExportConnectionRunStep exportRunStep)
        {
            try
            {
                this.GetMAConfig(configParameters);

                this.OpenRSAConnection();
            }
            catch (Exception ex)
            {
                EmailError(ex);
                throw ex;
            }
        }

        public PutExportEntriesResults PutExportEntries(IList<CSEntryChange> csentries)
        {
            PutExportEntriesResults exportEntriesResults = new PutExportEntriesResults();

            //int i = 0;

            foreach (CSEntryChange csentryChange in csentries)
            {
                userID = csentryChange.DN.ToString();

                if (csentryChange.ObjectType == "Person")
                {

                    // Code to Create RSA account
                    if (csentryChange.ObjectModificationType == ObjectModificationType.Add)
                    {
                        foreach (string attrib in csentryChange.ChangedAttributeNames)
                        {

                            switch (attrib)
                            {
                                case "First Name":
                                    firstName = csentryChange.AttributeChanges["First Name"].ValueChanges[0].Value.ToString();
                                    break;

                                case "Last Name":
                                    lastName = csentryChange.AttributeChanges["Last Name"].ValueChanges[0].Value.ToString();
                                    break;

                                case "Manager Email Address":
                                    managerEmailAddress = csentryChange.AttributeChanges["Manager Email Address"].ValueChanges[0].Value.ToString();
                                    break;

                                case "Middle Name":
                                    middleName = csentryChange.AttributeChanges["Middle Name"].ValueChanges[0].Value.ToString();
                                    break;
                                    
                            }


                        }


                        try
                        {
                            
                            AssignNewTokenToExistingUser(userID, managerEmailAddress, firstName, lastName);
                        }
                        catch (UserNotFoundException) 
                        {
                            CSEntryChangeResult error = CSEntryChangeResult.Create(csentryChange.Identifier, null, MAExportError.ExportErrorInvalidDN);
                            exportEntriesResults.CSEntryChangeResults.Add(error);

                            EmailError(new Exception("Unable to assign a token for user '" + userID + "'. User not found. The synchronization engine will try to assign a token on the next export."));
                        }
                         
                    }


                    // Code to Delete from RSA store
                    if (csentryChange.ObjectModificationType == ObjectModificationType.Replace)
                    {
                        //this.DeleteUser(userID);
                    }

                } // End of type Person

            } // End of ForEach

           // i++;

            
          

            return exportEntriesResults;
        }

        public void CloseExportConnection(CloseExportConnectionRunStep exportRunStep)
        {
            try
            {
                this.CloseRSAConnection();
            }
            catch (Exception ex)
            {
                EmailError(ex);
                throw ex;
            }
        }

        public int ImportMaxPageSize
        {
            get
            {
                return m_importMaxPageSize;
            }
        }

        public int ImportDefaultPageSize
        {
            get
            {
                return m_importDefaultPageSize;
            }
        }

        public int ExportDefaultPageSize
        {
            get
            {
                return m_exportDefaultPageSize;
            }
            set
            {
                m_exportDefaultPageSize = value;
            }
        }

        public int ExportMaxPageSize
        {
            get
            {
                return m_exportMaxPageSize;
            }
            set
            {
                m_exportMaxPageSize = value;
            }
        }

        private String SecureStringToString(SecureString value)
        {
            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
                return Marshal.PtrToStringUni(valuePtr);
             }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            return true;
        }
        
        private IdentitySourceDTO FindIdentitySource(IdentitySourceDTO[] identitySources)
        {
            foreach (IdentitySourceDTO src in identitySources)
            {
                if (src.name.Trim().ToLower() == m_IdentitySourceName.Trim().ToLower())
                    return src;
            }

            throw new Exception("Unable to find the specified identity source");
        }

        private void OpenRSAConnection()
        {

            ServicePointManager.ServerCertificateValidationCallback =
                    new RemoteCertificateValidationCallback(ValidateServerCertificate);

            m_Connection = new SOAPCommandTarget(m_RSAServer, m_CommandClientUserName, m_CommandClientPassword);

            if (!m_Connection.Login(m_AdministrativeUserName, m_AdministrativePassword, AuthenticationConstants.LDAP_PASSWORD_METHOD))
            {
                throw new Exception("Error: Unable to connect to the remote server. Please make sure your credentials are correct.");
            }

            CommandTargetPolicy.setDefaultCommandTarget(m_Connection);

            // Find Realm
            SearchRealmsCommand searchRealmCmd = new SearchRealmsCommand();
            searchRealmCmd.filter = (Filter.equal(RealmDTO.NAME_ATTRIBUTE, m_RSARealm));


            CommandTargetPolicy.getDefaultCommandTarget();
            searchRealmCmd.execute();
            RealmDTO[] realms = searchRealmCmd.realms;

            if (realms.Length == 0)
            {
                throw new Exception("Could not find realm " + m_RSARealm);
            }

            m_SecurityDomain = realms[0].topLevelSecurityDomain;
            m_IdentitySource = FindIdentitySource(realms[0].identitySources);
            // End of Find Realm
        }

        private void CloseRSAConnection()
        {
            m_Connection.Logout();
        }

        private List<RSAAccount> ImportUsers()
        {
            List<RSAAccount> rsaResult = new List<RSAAccount>();

            int countOne = 0, totalCount = 0;
            PrincipalDTO[] results;
            String searchContextId = null;

            SearchPrincipalsIterativeCommand cmd = new SearchPrincipalsIterativeCommand();
            cmd.limit = 100;
            cmd.identitySourceGuid = m_IdentitySource.guid;
            //cmd.filter = Filter.startsWith(PrincipalDTO.LOGINUID, "a");

            try
            {
                do
                {
                    cmd.execute();
                    searchContextId = cmd.searchContextId;
                    results = cmd.principals;
                    countOne = results.Length;
                    if (countOne <= 0)
                    {
                        break;
                    }
                    totalCount += countOne;


                    foreach (PrincipalDTO principal in results) 
                    {
                        ListTokenDTO[] tokens = ListTokensForUser(principal.guid);
                        
                        if (tokens.Length > 0)
                            rsaResult.Add(new RSAAccount(principal, tokens));
                    }


                }
                while (true);
            }

            finally
            {
                if (searchContextId != null)
                {

                    EndSearchPrincipalsIterativeCommand endSearch = new EndSearchPrincipalsIterativeCommand();
                    endSearch.searchContextId = searchContextId;
                    endSearch.execute();
                }
            }

            return rsaResult;
        }

        private ListTokenDTO[] ListTokensForUser(string userGuid) 
        {
            ListTokensByPrincipalCommand getTokensCommand = new ListTokensByPrincipalCommand();
            getTokensCommand.principalId = userGuid;

            getTokensCommand.execute();

            return getTokensCommand.tokenDTOs;
        }

        private void DeleteUser(string userID)
        {
            string userGuid = LookupUser(userID);

            DeletePrincipalsCommand cmd = new DeletePrincipalsCommand();
            cmd.guids = new String[] { userGuid };
            cmd.identitySourceGuid = m_IdentitySource.guid;
            cmd.execute();
        }

        private string LookupUser(string userID)
        {
            SearchPrincipalsCommand cmd = new SearchPrincipalsCommand();

            cmd.filter = (Filter.equal(PrincipalDTO.LOGINUID, userID));
            cmd.systemFilter = (Filter.empty());
            cmd.limit = (1);
            cmd.identitySourceGuid = m_IdentitySource.guid;
            //cmd.securityDomainGuid = m_SecurityDomain.guid;
            //cmd.groupGuid = (null);
            //cmd.onlyRegistered = (true);
            cmd.searchSubDomains = (true);

            cmd.execute();

            if (cmd.principals.Length == 0)
                throw new Exception("Unable to find user with user id " + userID + ".");

            return cmd.principals[0].guid;
        }

        private void AssignNewTokenToExistingUser(string userID, string managerEmailAddress, string aFirstName, string aLastName) 
        {
            string userGUID;
            try
            {
                userGUID = this.LookupUser(userID);
            }

            catch (Exception)
            {
                throw new UserNotFoundException();
            }

            TokenDTO tokenObject = AssignNextAvailableTokenToUser(userGUID);

            SendToken(managerEmailAddress, tokenObject, userID, aFirstName, aLastName);
        }


        private string CreateIMSUser(string userID, string firstName, string middleName, string lastName, DateTime expiryDate, string password)
        {

            PrincipalDTO principal = new PrincipalDTO();
            principal.userID = userID;
            principal.firstName = firstName;
            principal.middleName = middleName;
            principal.lastName = lastName;
            principal.password = password;

            principal.enabled = true;
            principal.accountStartDate = DateTime.Now;
            principal.accountExpireDate = expiryDate;

            principal.canBeImpersonated = (false);
            principal.trustToImpersonate = (false);

            principal.securityDomainGuid = m_SecurityDomain.guid;
            principal.identitySourceGuid = m_IdentitySource.guid;

            //require user to change password at next login
            principal.passwordExpired = (true);

            AddPrincipalsCommand cmd = new AddPrincipalsCommand();
            cmd.principals = (new PrincipalDTO[] { principal });

            cmd.execute();

            return cmd.guids[0];
        }

        private void CreateAMUser(string userGuid, string password)
        {
            AMPrincipalDTO principal = new AMPrincipalDTO();
            principal.guid = userGuid;
            principal.defaultShell = m_DefaultShell;
            principal.defaultUserIdShellAllowed = true;
            principal.staticPassword = password;
            principal.staticPasswordSet = true;
            principal.windowsPassword = password;

            AddAMPrincipalCommand cmd = new AddAMPrincipalCommand();
            cmd.amp = principal;

            cmd.execute();
        }

        private TokenDTO AssignNextAvailableTokenToUser(string userGuid)
        {
            // Gets the next availalbe token
            GetNextAvailableTokenCommand availableToken = new GetNextAvailableTokenCommand();
            try
            {
                availableToken.execute();
            }
            catch (com.rsa.command.exception.DataNotFoundException)
            {
                throw new Exception("No available tokens.");
            }

            // Update Pin Type
            if (availableToken.token.pinType != TokenConstants.USE_TOKENCODE)
            {
                SetTokenPinTypeCommand cmdPin = new SetTokenPinTypeCommand();
                cmdPin.pinType = TokenConstants.USE_TOKENCODE;
                cmdPin.tokenGuids = new string[] { availableToken.token.id };
                cmdPin.execute();
            }

            // Get the Token Again by Guid after updating pin type
            LookupTokenCommand getToken = new LookupTokenCommand();
            getToken.guid = availableToken.token.id;
            getToken.execute();


            // assing token to the user
            String[] tokens = new String[] { getToken.token.id };
            LinkTokensWithPrincipalCommand attachTokenToPrincipal = new LinkTokensWithPrincipalCommand();
            attachTokenToPrincipal.tokenGuids = tokens;
            attachTokenToPrincipal.principalGuid = userGuid;
            attachTokenToPrincipal.execute();

            return getToken.token;
        }

        private void SendToken(string managerEmailAddress, TokenDTO tokenObject, string userID, string aFirstName, string aLastName)
        {
            LookupSoftTokenDeviceTypeCommand devType = new LookupSoftTokenDeviceTypeCommand();
            devType.softTokenDeviceTypeGuid = tokenObject.softTokenDeviceTypeId;
            devType.execute();
            SoftTokenDeviceTypeDTO dt = devType.softTokenDeviceTypeDTO;

            IssueSoftwareTokensCommand issueCmd = new IssueSoftwareTokensCommand();
            DistributeSoftTokenRequest request = new DistributeSoftTokenRequest();
            request.tokenGuids = new String[] { tokenObject.id };
            request.deviceTypeGuid = tokenObject.softTokenDeviceTypeId;
            request.deviceTypePluginModuleName = dt.pluginModuleName;
            request.protectedMethod = -1;

            // can set other options here...
            //request.protectedMethod = IssueSoftTokenRequestBase.ST_PROTECTED_BY_USERID;
            //request.protectedMethod = IssueSoftTokenRequestBase.ST_PROTECTED_BY_PASSWORD;
            //request.password = "password1";
            //request.copyProtected = false;

            // issue token

            //x-rimdevice<username>.sdtid


            issueCmd.request = request;
            issueCmd.execute();

            // retrieve output
            GetSoftwareTokenFileCommand tokenFile = new GetSoftwareTokenFileCommand();
            tokenFile.fileId = issueCmd.fileId;
            tokenFile.execute();

            byte[] output = tokenFile.fileContent;

            // write to filesystem
            string zipfilePath = m_TokenFilePath.Trim() + "\\" + userID + "(" + tokenObject.serialNumber + ").zip";
            // delete the file if it exists.
            if (System.IO.File.Exists(zipfilePath))
            {
                System.IO.File.Delete(zipfilePath);
            }

            // create the file.
            using (System.IO.FileStream fs = System.IO.File.Create(zipfilePath, 1024))
            {
                fs.Write(output, 0, output.Length);
            }

            // Unzip and rename token
            string newTokenPath = "";
            using (var zip = ZipFile.Read(zipfilePath))
            {

                foreach (ZipEntry e in zip.Entries)
                {
                    if (e.FileName.EndsWith("sdtid"))
                    {
                        e.Extract(m_TokenFilePath.Trim(), ExtractExistingFileAction.OverwriteSilently);
                        newTokenPath = m_TokenFilePath.Trim() + "\\x-rimdevice(" + userID + ").sdtid";
                        System.IO.File.Move(m_TokenFilePath.Trim() + "\\" + e.FileName, newTokenPath);
                    }
                }
            }
            // Delete zip file
            File.Delete(zipfilePath);


            //Send Email
            System.Net.Mail.MailMessage message = new System.Net.Mail.MailMessage();
            message.To.Add(managerEmailAddress);

            string[] ccArray = m_OtherTokenReceivers.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string emailCC in ccArray)
                message.CC.Add(emailCC.Trim());

            message.Subject = "RSA Token for " + aLastName + ", " + aFirstName;
            message.From = new System.Net.Mail.MailAddress(m_Sender);
            message.Body = "Please see the attached RSA Token file for " + aLastName +", "+ aFirstName;
            message.Attachments.Add(new System.Net.Mail.Attachment(newTokenPath));
            System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient(m_SMTPHost);
            smtp.Send(message);

        }

        private void EmailError(Exception ex)
        {
            System.Net.Mail.MailMessage message = new System.Net.Mail.MailMessage();
            message.To.Add(m_ErrorsMail.Trim());
            message.From = new System.Net.Mail.MailAddress(m_Sender);

            message.Subject = "RSA Server - Error Occurred";
            message.Body = "An Error Occurred - Details:\n" + ex.Message;

            if (ex.InnerException != null)
                message.Body += "\n\nInner Exception:\n" + ex.InnerException.Message;

            message.Body += "\n\nStack Trace:\n" + ex.StackTrace;

            System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient(m_SMTPHost);
            smtp.Send(message);
        }

    };
}
