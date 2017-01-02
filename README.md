# wso2-secure-vault-configuration

Create WSO2 Secure Vault configuration

This repository contains a perl script that simplifies the use of [WSO2's Secure Vault](https://docs.wso2.com/display/Carbon440/Securing+Passwords+in+Configuration+Files) feature.

The script scans the configuration files of a WSO2 product for plain text passwords and generates
the configuration files

    cipher-text.properties
    cipher-tool.properties

from the collected information.


## Prerequisites

    - perl 5.008 and newer
    - perl modules :

    - Carp
    - File::Basename
    - File::Find
    - File::Spec
    - Getopt::Long
    - Getopt::Std
    - IO::File
    - Time::HiRes
    - XML::Parser
    - XML::SAX::ParserFactory
    - XML::Simple
 
## Tested with WSO2 API Manager 

    - version 1.10

## Tested on 

    - Fedora 22, 24, 25
    - Centos7
    - Cygwin 


## Usage

    wso2ciphertoolconfig.pl [-dhvx] <carbonhome>"

        -d      debug
        -h      print usage and exit
        -v      be verbose
        -x      list available SAX parsers and exit
                (this is for debugging only)


## Step 1 : Generate Secure Vault properties files

Install the scripts and the prerequisite perl modules, then execute the script as

    [axel@fc25 bin]$ ./wso2ciphertoolconfig.pl -v /opt/wso2/wso2am-1.10

Adapt the <carbonhome> location to your installation.


Sample output 

    FILE : /opt/wso2/wso2am-1.10/repository/conf/api-manager.xml
    ====>: /APIManager/AuthManager/Password=[j7W4zQmLgjnFvBMP]
    ====>: /APIManager/APIGateway/Environments/Environment/Password=[j7W4zQmLgjnFvBMP]
    ====>: /APIManager/APIUsageTracking/DASPassword=[admin]
    ====>: /APIManager/APIUsageTracking/DASRestApiPassword=[admin]
    ====>: /APIManager/APIKeyValidator/Password=[j7W4zQmLgjnFvBMP]
    ====>: /APIManager/APIStore/Password=[j7W4zQmLgjnFvBMP]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/axis2/axis2.xml
    ====>: /axisconfig/transportReceiver[@name='https']/parameter[@name='keystore']/KeyStore/Password=[wso2carbon]
    ====>: /axisconfig/transportReceiver[@name='https']/parameter[@name='keystore']/KeyStore/KeyPassword=[wso2carbon]
    ====>: /axisconfig/transportReceiver[@name='https']/parameter[@name='truststore']/TrustStore/Password=[wso2carbon]
    ====>: /axisconfig/transportSender[@name='https']/parameter[@name='keystore']/KeyStore/Password=[wso2carbon]
    ====>: /axisconfig/transportSender[@name='https']/parameter[@name='keystore']/KeyStore/KeyPassword=[wso2carbon]
    ====>: /axisconfig/transportSender[@name='https']/parameter[@name='truststore']/TrustStore/Password=[wso2carbon]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/axis2/axis2_blocking_client.xml
    ====>: /axisconfig/parameter[@name='password']=[axis2]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/axis2/axis2_client.xml
    ====>: /axisconfig/parameter[@name='password']=[axis2]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/carbon.xml
    ====>: /Server/Security/KeyStore/Password=[wso2carbon]
    ====>: /Server/Security/KeyStore/KeyPassword=[wso2carbon]
    ====>: /Server/Security/TrustStore/Password=[wso2carbon]
    ====>: /Server/DeploymentSynchronizer/SvnPassword=[password]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/datasources/master-datasources.xml
    ====>: /datasources-configuration/datasources/datasource[name='WSO2_CARBON_DB']/definition[@type='RDBMS']/configuration/password=[wso2carbon]
    ====>: /datasources-configuration/datasources/datasource[name='WSO2AM_DB']/definition[@type='RDBMS']/configuration/password=[mysqlpass]
    ====>: /datasources-configuration/datasources/datasource[name='WSO2UM_DB']/definition[@type='RDBMS']/configuration/password=[mysqlpass]
    ====>: /datasources-configuration/datasources/datasource[name='WSO2AM_STATS_DB']/definition[@type='RDBMS']/configuration/password=[mysqlpass]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/datasources/metrics-datasources.xml
    ====>: /datasources-configuration/datasources/datasource[name='WSO2_METRICS_DB']/definition[@type='RDBMS']/configuration/password=[wso2carbon]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/identity/application-authentication.xml
    ====>: /ApplicationAuthentication/AuthenticatorConfigs/AuthenticatorConfig[@name='OpenIDAuthenticator']/Parameter[@name='TrustStorePassword']=[wso2carbon]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/identity/identity.xml
    ====>: /Server/MultifactorAuthentication/XMPPSettings/XMPPConfig/XMPPPassword=[wso2carbon]
    ====>: /Server/EntitlementSettings/ThirftBasedEntitlementConfig/KeyStore/Password=[wso2carbon]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/tomcat/catalina-server.xml
    ====>: /Server/Service/Connector[@keystorePass]=[wso2carbon]

    FILE : /opt/wso2/wso2am-1.10/repository/conf/user-mgt.xml
    ====>: /UserManager/Realm/Configuration/AdminUser/Password=[j7W4zQmLgjnFvBMP]

    Found 28 passwords in 11 out of 45 files.
    Created output files :
    /opt/wso2/wso2am-1.10/repository/conf/security/cipher-tool.properties
    /opt/wso2/wso2am-1.10/repository/conf/security/cipher-text.properties

In verbose mode (with the '-v' option) the script logs every password with an XPath expression specifying the password location 
and the actual password (trailing the line in '[',']' ).


## Step 2 : Run the Secure Vault ciphertool utility

Now you can run WSO2's ciphertool.sh script (that comes with the product) to go over the configuration files 
and encrypt the plaintext passwords in the configuration files :

    [axel@fc25 bin]$ export CARBON_HOME=/opt/wso2/wso2am-1.10
    [axel@fc25 bin]$ export JAVA_HOME=/opt/jdk1.8.0_60
    [axel@fc25 bin]$ export PATH=$JAVA_HOME/bin:$PATH
    [axel@fc25 bin]$ ${CARBON_HOME}/bin/ciphertool.sh -Dconfigure -Dpassword=wso2carbon


The 'wso2runjavaciphertool.sh' from the repository wraps this into a single command. 
It also takes care of a [pending issue in WSO2 API Manager 1.10](https://wso2.org/jira/browse/IDENTITY-4276).
(If the password is not provided on the command line with the '-p' option, the tool will prompt for it interactively).
    
    [axel@fc25 bin]$ ./wso2runjavaciphertool.sh -p wso2carbon /opt/wso2/wso2am-1.10
    
    Primary KeyStore of Carbon Server is initialized Successfully
    Protected Token [Axis2.Https.Listener.TrustStore.Password] is updated in repository/conf/axis2/axis2.xml successfully
    Protected Token [APIUsageTracking.DASPassword] is updated in repository/conf/api-manager.xml successfully
    Protected Token [UserManager.AdminUser.Password] is updated in repository/conf/user-mgt.xml successfully
    Protected Token [Axis2.Https.Sender.TrustStore.Password] is updated in repository/conf/axis2/axis2.xml successfully
    Protected Token [Axis2.Https.Sender.KeyStore.Password] is updated in repository/conf/axis2/axis2.xml successfully
    Protected Token [APIKeyValidator.Password] is updated in repository/conf/api-manager.xml successfully
    Protected Token [APIGateway.Password] is updated in repository/conf/api-manager.xml successfully
    Protected Token [AuthenticatorConfigs.OpenIDAuthenticator.TrustStorePassword] is updated in repository/conf/identity/application-authentication.xml successfully
    Protected Token [Axis2.Https.Listener.KeyStore.Password] is updated in repository/conf/axis2/axis2.xml successfully
    Protected Token [Axis2.client] is updated in repository/conf/axis2/axis2_client.xml successfully
    Protected Token [datasources.WSO2REG_DB.RDBMS.configuration.password] is updated in repository/conf/datasources/master-datasources.xml successfully
    Protected Token [APIStore.Password] is updated in repository/conf/api-manager.xml successfully
    Protected Token [Axis2.Https.Listener.KeyStore.KeyPassword] is updated in repository/conf/axis2/axis2.xml successfully
    Protected Token [Axis2.Https.Sender.KeyStore.KeyPassword] is updated in repository/conf/axis2/axis2.xml successfully
    Protected Token [DeploymentSynchronizer.SvnPassword] is updated in repository/conf/carbon.xml successfully
    Protected Token [Carbon.Security.TrustStore.Password] is updated in repository/conf/carbon.xml successfully
    Protected Token [Axis2.blockingclient] is updated in repository/conf/axis2/axis2_blocking_client.xml successfully
    Protected Token [EntitlementSettings.ThirftBasedEntitlementConfig.KeyStore.Password] is updated in repository/conf/identity/identity.xml successfully
    Protected Token [datasources.WSO2_METRICS_DB.RDBMS.configuration.password] is updated in repository/conf/datasources/metrics-datasources.xml successfully
    Protected Token [Carbon.Security.KeyStore.KeyPassword] is updated in repository/conf/carbon.xml successfully
    Protected Token [AuthManager.Password] is updated in repository/conf/api-manager.xml successfully
    Protected Token [datasources.WSO2_CARBON_DB.RDBMS.configuration.password] is updated in repository/conf/datasources/master-datasources.xml successfully
    Protected Token [datasources.WSO2AM_DB.RDBMS.configuration.password] is updated in repository/conf/datasources/master-datasources.xml successfully
    Protected Token [datasources.WSO2AM_STATS_DB.RDBMS.configuration.password] is updated in repository/conf/datasources/master-datasources.xml successfully
    Protected Token [datasources.WSO2UM_DB.RDBMS.configuration.password] is updated in repository/conf/datasources/master-datasources.xml successfully
    Protected Token [MultifactorAuthentication.XMPPSettings.XMPPConfig.XMPPPassword] is updated in repository/conf/identity/identity.xml successfully
    Protected Token [Server.Service.Connector.keystorePass] is updated in repository/conf/tomcat/catalina-server.xml successfully
    Protected Token [Carbon.Security.KeyStore.Password] is updated in repository/conf/carbon.xml successfully
    Protected Token [APIUsageTracking.DASRestApiPassword] is updated in repository/conf/api-manager.xml successfully
    Encryption is done Successfully
    Encryption is done Successfully
    Encryption is done Successfully
    .
    .
    Encryption is done Successfully
    Encryption is done Successfully
    Secret Configurations are written to the property file successfully


## Starting the API Manager with encrypted passwords

After [creating a temporary password file](https://docs.wso2.com/display/Carbon440/Resolving+Encrypted+Passwords)

    <CARBON_HOME>/password-tmp

with the password for the carbon keystore you can now start the API Manager.


## Known Bugs

The perl script throws a warning when parsing user-mgt.xml. 

    Warning: <Property> element has non-unique value in 'name' key attribute: MaxUserNameListLength at ./wso2ciphertoolconfig.pl line 333.

This can be ignored since the warning is correct.
```xml
('<Property name="MaxUserNameListLength">100</Property>' is defined twice in user-mgt.xml).
```
