#!/bin/bash
# -------------------------------------------------------------- #
# wso2runjavaciphertool.sh                               v 1.0   #
#                                                                #
# run the the ciphertool utility to encrypt the plaintext        #
# passwords in the wso2 secure vault ciphertext-properties       #
# configuration file of an installed product and replace the     #
# plaintext passwords in the wso2 configuration files by         #
# an alias reference to the encrypted password.                  #
#                                                                #
# -------------------------------------------------------------- #
#                                                                #
#  Options    :                                                  #
#                                                                #
#  -h              print help                                    #
#  -change         execute the ciphertool for 'change'           #
#                                                                #
# -------------------------------------------------------------- #
#                                                                #
#  Parameters :                                                  #
#                                                                #
#  ${1}	           CARBON_HOME directory of installed product    #
#                                                                #
# -------------------------------------------------------------- #
#                                                                #
#  Environment Variables                                         #
#                                                                #
#  JAVA_HOME       optional, if undefined the script tries to    #
#                  derive JAVA_HOME from the location of the     #
#                  'java' executable.                            #
#                                                                #
# -------------------------------------------------------------- #
#                                                                #
# return codes :                                                 #
#                                                                #
#  0     operation successful                                    #
#  1     operation not started                                   #
# -4     parameters invalid                                      #
# -8     no java installation found                              #
# 16     operation of ciphertool utility was aborted             #
#                                                                #
# -------------------------------------------------------------- #

#set -vx

export usage="usage: $(basename ${0}) [-change] [-p <storekeypassword>] <carbonhome>"
export hostname=$(hostname -f)

##
#   process options
## 

opisupdate=''

while [[ "${1}" =~ ^-.* ]];
do
    case "${1}" in
      -change) opisupdate='yes';
            shift
            ;;
      -h)   echo "$usage";
            exit 1
            ;;
      -p)   storekeypass="-Dpassword=${2}";
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
    echo "<carbonhome> is not defined"
    echo "$usage";
    exit 1
fi

if [ ! -d "${carbonhome}" ]; then
    echo "CARBON_HOME directory ${carbonhome} does not exist"
    exit -4
fi

##
# update environment variables
##

export CARBON_HOME=${carbonhome}

if [ x"${JAVA_HOME}" == x ]; then
    javabin=$(which java)
    if [ ! x"${javabin}" == x ]; then
        echo "no 'java' executable found"
        exit -8
    fi
    javabin=$(dirname $(readlink -f $javabin))
    export JAVA_HOME=$(readlink -f "$javabin/..")
fi

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

echo "CARBONHOME : ${CARBON_HOME}"
echo "JAVA_HOME  : $JAVA_HOME"

##
# execute the ciphertool utility.
##

ciphertooloperation='configure'
if [ x$opisupdate != x ]; then
	ciphertooloperation='change'
fi

$JAVA_HOME/bin/java -Dcarbon.home="$CARBON_HOME" -classpath "$CARBON_CLASSPATH" org.wso2.ciphertool.CipherTool -D${ciphertooloperation} $storekeypass
if [ $? -ne 0 ]; then
	exit 16
fi

exit 0
