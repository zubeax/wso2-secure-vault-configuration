#!/bin/bash
# -------------------------------------------------------------- #
# wso2runjavaciphertool.sh                               v 1.0   #
#                                                                #
# run the the ciphertool utility to encrypt the plaintext        #
# passwords in the wso2 secure vault ciphertext-properties       #
# configuration file of an installed product and replace the     #
# plaintext passwords in the wso2 configuration files by         #
# an alias reference to the encrypted password.                  #
# -------------------------------------------------------------- #
#                                                                #
#  Options    :                                                  #
#                                                                #
#  -h              print help                                    #
#  -change         execute the ciphertool for 'change'           #
#                                                                #
#  Parameters :                                                  #
#                                                                #
#  ${1}	 : wso2 api manager product                              #
#                                                                #
# -------------------------------------------------------------- #

#set -vx

export usage="usage: $(basename ${0}) [-change] singlenode|gateway|keymanager|pubstore"
export hostname=$(hostname -f)

##
#   process options
## 

lockstore=''
opisupdate=''
debugopts=''

while [[ "${1}" =~ ^-.* ]];
do
    case "${1}" in
      -change) opisupdate='yes';
            shift
            ;;
      -h)   echo "$usage";
            exit 1
            ;;
      -p)   storekeypass="${2}";
            shift;
            shift;
            ;;
      *)    shift
            ;;
    esac
done

carbonhome="${1}"

##
#   verify existence of directories
##

if [ x"${carbonhome}" == x ]; then
    echo "CARBON_HOME is not defined"
    exit 1
fi

if [ ! -d "${carbonhome}" ]; then
    echo "CARBON_HOME directory ${carbonhome} does not exist"
    exit -4
fi

export CARBON_HOME=${carbonhome}

javabin=$(dirname $(readlink -f $(which java)))
export JAVA_HOME=$(readlink -f "$javabin/..")

export PATH=${JAVA_BASE}/bin:${CARBON_HOME}/bin:$PATH

# CAVEAT:   As reported in https://wso2.org/jira/browse/IDENTITY-4276,
#           there are problems with processing the plaintext passwords from
#
#               ${CARBON_HOME}/repository/conf/identity/EndpointConfig.properties
#
# INTERMEDITATE RESOLUTION 
#
#           use the sed commands below to replace the plaintext passwords by alias references

endpointconfig="repository/conf/identity/EndpointConfig.properties"

sed -i -e "s/\(Carbon.Security.KeyStore.Password\)=.*$/\1=secretAlias:\1/g"    "${CARBON_HOME}"/$endpointconfig
sed -i -e "s/\(Carbon.Security.TrustStore.Password\)=.*$/\1=secretAlias:\1/g"  "${CARBON_HOME}"/$endpointconfig

##
# collect the jars required to run the ciphertool utility in the classpath
##
CARBON_CLASSPATH=""
for f in "$CARBON_HOME"/lib/org.wso2.ciphertool*.jar
do
    CARBON_CLASSPATH=$CARBON_CLASSPATH:$f
done

for h in "$CARBON_HOME"/repository/components/plugins/*.jar
do
    CARBON_CLASSPATH=$CARBON_CLASSPATH:$h
done

CARBON_CLASSPATH=$CARBON_CLASSPATH:$CLASSPATH

echo "CARBONHOME      : ${CARBON_HOME}"
echo "JAVA_HOME       : $JAVA_HOME"

##
# execute the ciphertool utility. compress the output by removing empty lines
##

ciphertooloperation='configure'
if [ x$opisupdate != x ]; then
	ciphertooloperation='change'
fi

$JAVA_HOME/bin/java ${debugopts} -Dcarbon.home="$CARBON_HOME" -classpath "$CARBON_CLASSPATH" org.wso2.ciphertool.CipherTool -D${ciphertooloperation} -Dpassword=$storekeypass
if [ $? -ne 0 ]; then
	exit 16
fi

exit 0
