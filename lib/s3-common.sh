#!/usr/bin/env bash
#
# Common functions for s3-bash4 commands
# (c) 2015 Chi Vinh Le <cvl@winged.kiwi>

# Constants
readonly VERSION="1.0.0"

# Exit codes
readonly INVALID_USAGE_EXIT_CODE=1
readonly INVALID_USER_DATA_EXIT_CODE=2
readonly INVALID_ENVIRONMENT_EXIT_CODE=3

##
# Write error to stderr
# Arguments:
#   $1 string to output
##
err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Error: $@" >&2
}


##
# Display version and exit
##
showVersionAndExit() {
  printf "$VERSION\n"
  exit
}

##
# Helper for parsing the command line.
##
assertArgument() {
  if [[ $# -lt 2 ]]; then
    err "Option $1 needs an argument."
    exit $INVALID_USAGE_EXIT_CODE
  fi
}

##
# Asserts given resource path
# Arguments:
#   $1 string resource path
##
assertResourcePath() {
  if [[ $1 = !(/*) ]]; then
    err "Resource should start with / e.g. /bucket/file.ext"
    exit $INVALID_USAGE_EXIT_CODE
  fi
}

##
# Asserts given file exists.
# Arguments:
#   $1 string file path
##
assertFileExists() {
  if [[ ! -f $1 ]]; then
    err "$1 file doesn't exist"
    exit $INVALID_USER_DATA_EXIT_CODE
  fi
}

##
# Check for valid environment. Exit if invalid.
##
checkEnvironment()
{
  programs=(openssl curl printf echo sed awk od date shasum pwd dirname\
            cut fgrep tail head)
  for program in "${programs[@]}"; do
    if [ ! -x "$(which $program)" ]; then
      err "$program is required to run"
      exit $INVALID_ENVIRONMENT_EXIT_CODE
    fi
  done
}

##
# Reads, validates and return aws secret stored in AWS credentials
# Arguments:
#   $1 profile name
# Output:
#   string AWS secret
##
getSecretFromAWSCredentials() {
  local credentials=$(fgrep -A 2 ${1:-default}\
                     $HOME/.aws/credentials | tail -n 2)
  local secret=$(echo "$credentials" | fgrep secret | cut -f2 -d= | sed "s/ //")

  # exact string size should be 40.
  if [[ ${#secret} != 40 ]]; then
    err $errStr
    exit $INVALID_USER_DATA_EXIT_CODE
  fi
  echo "$secret"
}

##
# Reads, validates and return aws access key stored in AWS credentials
# Arguments:
#   $1 profile name
# Output:
#   string AWS Access key
##
getAccessKeyFromAWSCredentials() {
  local credentials=$(fgrep -A 2 ${1:-default}\
                     $HOME/.aws/credentials | tail -n 2)
  local key=$(echo "$credentials" | fgrep id | cut -f2 -d= | sed "s/ //")
  echo "$key"
}

##
# Reads default region from the profile selected
# Arguments:
#   $1 profile name
# Output:
#   string region name
##
getDefaultRegionFromProfile() {
  fgrep -A 2 ${1:-default} $HOME/.aws/config | \
    tail -n 2                                | \
    fgrep region                             | \
    cut -d = -f 2                            | \
    tr -d ' '
}

##
# Reads, validates and return aws secret stored in a file
# Arguments:
#   $1 path to secret file
# Output:
#   string AWS secret
##
processAWSSecretFile() {
  local errStr="The Amazon AWS secret key must be 40 bytes long. Make sure that there is no carriage return at the end of line."
  if ! [[ -f $1 ]]; then
    err "The file $1 does not exist."
    exit $INVALID_USER_DATA_EXIT_CODE
  fi

  # limit file size to max 41 characters. 40 + potential null terminating character.
  local fileSize="$(ls -l "$1" | awk '{ print $5 }')"
  if [[ $fileSize -gt 41 ]]; then
    err $errStr
    exit $INVALID_USER_DATA_EXIT_CODE
  fi

  secret=$(<$1)
  # exact string size should be 40.
  if [[ ${#secret} != 40 ]]; then
    err $errStr
    exit $INVALID_USER_DATA_EXIT_CODE
  fi
  echo $secret
}

##
# Convert string to hex with max line size of 256
# Arguments:
#   $1 string to convert
# Returns:
#   string hex
##
hex256() {
  printf "$1" | od -A n -t x1 | sed ':a;N;$!ba;s/[\n ]//g'
}

##
# Calculate sha256 hash
# Arguments:
#   $1 string to hash
# Returns:
#   string hash
##
sha256Hash() {
  local output=$(printf '%b' "$1" | shasum -a 256)
  echo "${output%% *}"
}

##
# Calculate sha256 hash of file
# Arguments:
#   $1 file path
# Returns:
#   string hash
##
sha256HashFile() {
  local output=$(shasum -a 256 $1)
  echo "${output%% *}"
}

##
# Generate HMAC signature using SHA256
# Arguments:
#   $1 signing key in hex
#   $2 string data to sign
# Returns:
#   string signature
##
hmac_sha256() {
  printf '%b' "$2" | openssl dgst -binary -hex -sha256 \
                     -mac HMAC -macopt hexkey:$1       \
                   | sed 's/^.* //'
}

##
# Sign data using AWS Signature Version 4
# Arguments:
#   $1 AWS Secret Access Key
#   $2 yyyymmdd
#   $3 AWS Region
#   $4 AWS Service
#   $5 string data to sign
# Returns:
#   signature
##
sign() {
  local kSigning=$(hmac_sha256 $(hmac_sha256 $(hmac_sha256 \
                 $(hmac_sha256 $(hex256 "AWS4$1") $2) $3) $4) "aws4_request")
  hmac_sha256 "${kSigning}" "$5"
}

##
# Get endpoint of specified region
# Arguments:
#   $1 region
# Returns:
#   amazon andpoint
##
convS3RegionToEndpoint() {
  case "$1" in
    us-east-1) echo "s3.amazonaws.com"
      ;;
    *) echo s3-${1}.amazonaws.com
      ;;
    esac
}

##
# Url encode a string
#   $1 string
##
urlEncode() {
  local LANG=C
  local length="${#1}"
  for (( i = 0; i < length; i++ )); do
    local c="${1:i:1}"
    case $c in
      [a-zA-Z0-9.~_-]) printf "$c" ;;
      *) printf '%%%02X' "'$c" ;;
    esac
  done
}

##
# Quick sort
#  $1 array
##
qsort() {
  local pivot i smaller=() larger=()
  qsort_ret=()
  (($#==0)) && return 0
  pivot=$1
  shift
  for i; do
    if [[ "$i" < "$pivot" ]]; then
      smaller+=( "$i" )
    else
      larger+=( "$i" )
    fi
  done
  qsort ${larger[@]+"${larger[@]}"}
  larger=( ${qsort_ret[@]+"${qsort_ret[@]}"} )
  qsort ${smaller[@]+"${smaller[@]}"}
  qsort_ret+=( "$pivot" ${larger[@]+"${larger[@]}"})
}

##
# Perform request to S3
# Uses the following Globals:
#   AWS_ACCESS_KEY_ID     string
#   AWS_SECRET_ACCESS_KEY string
#   AWS_REGION            string
#   RESOURCE_PATH         string
#   PUBLISH               bool
#   DEBUG                 bool
#   VERBOSE               bool
#   INSECURE              bool
#   OPTIONS               array
##
performGenericRequest() {
  local timestamp=$(date -u "+%Y-%m-%d %H:%M:%S")
  local isoTimestamp=$(date -ud "${timestamp}" "+%Y%m%dT%H%M%SZ")
  local dateScope=$(date -ud "${timestamp}" "+%Y%m%d")
  local host=$(printf '%b' "${RESOURCE_PATH}" |sed 's/^.*:\/\///' |cut -f1 -d/)
  local requestPath=$RESOURCE_PATH
  local resourcePath=$(printf '%b' "${RESOURCE_PATH}" \
                        |sed 's/^.*:\/\///' |cut -f2- -d/)
  local queryString=$(echo "$resourcePath" |cut -f2 -d\?)
  resourcePath=$(echo "$resourcePath" | cut -f1 -d\?)
  resourcePath=$(urlEncode "/$resourcePath"|sed 's/%2F/\//g')

  local payloadHash=$(sha256Hash "")
  local cmd=("curl")
  local headers=
  local headerList=

  if [[ ${DEBUG} != true ]]; then
    cmd+=("--fail")
  fi

  if [[ ${VERBOSE} == true ]]; then
    cmd+=("--verbose")
  fi

  for ((inx=0; inx<${#OPTIONS[*]}; inx+=2));
  do
    if [[ "${OPTIONS[inx]}" == "-s" ]]; then
      cmd+=("-s") # TODO: Generalize single item options
      inx=$((inx-1))
    elif [[ "${OPTIONS[inx]}" == "-I" ]]; then
      cmd+=("-I") # TODO: Generalize single item options
      inx=$((inx-1))
    else
      cmd+=("${OPTIONS[inx]}" "${OPTIONS[inx+1]}")
    fi
    # Generate payload hash
    if [[ "${OPTIONS[inx]}" == "-T" ]]; then
      payloadHash=$(sha256HashFile "${OPTIONS[inx+1]}") 
    fi
  done

  cmd+=("-H" "Host: ${host}")
  cmd+=("-H" "x-amz-content-sha256: ${payloadHash}")
  cmd+=("-H" "x-amz-date: ${isoTimestamp}")

  headersArr=()
  for ((inx=0; inx<${#cmd[*]}; inx++));
  do
    if [[ ${cmd[inx]} == '-H' ]]; then
      headersArr+=("${cmd[inx+1]}")
    fi
  done
  # Sort headers array
  qsort "${headersArr[@]}"
  headersArr=("${qsort_ret[@]}")

  # Construct canonical headers
  for ((inx=0; inx<${#headersArr[*]}; inx++));
  do
    IFS=': ' read -r -a headerParts <<< "${headersArr[inx]}"
    canonicalHeaderName=${headerParts[0],,} #bash 4+
    headers+="${canonicalHeaderName}:${headerParts[1]}
" # TODO: Figure out why \n doesn't work here
    headerList+="${canonicalHeaderName};"
  done
  headerList="${headerList%?}" # Remove last letter (the ;)
  headers="${headers%?}" # Remove last newline

  # TODO: handle special query strings
  # TODO: sort query strings
  if [ ! -z "{$queryString}" ] && [ /${queryString} != ${resourcePath} ]; then
    IFS='&' read -r -a queryStringKeyValuePairs <<< "${queryString}"
    queryString=''
    for ((inx=0; inx<${#queryStringKeyValuePairs[*]}; inx++));
    do
      IFS='=' read -r -a queryStringParts <<< "${queryStringKeyValuePairs[inx]}"
      # At this point we should only have two items: key at index 0, value at 1
      queryString+=$(urlEncode  ${queryStringParts[0]})\
=$(urlEncode ${queryStringParts[1]})
      queryString+='&'
    done
    queryString="${queryString%?}" # Remove last newline
  fi
  # Generate canonical request
  local canonicalRequest="${METHOD}
${resourcePath}
${queryString}
${headers}

${headerList}
${payloadHash}"

  # Generated request hash
  local hashedRequest=$(sha256Hash "${canonicalRequest}")

  # TODO: Determine service by URL
  # cloudformation.region.amazonaws.com: cloudfront
  # s3.amazonaws.com: s3
  local awsService=s3

  # Generate signing data
  local stringToSign="AWS4-HMAC-SHA256
${isoTimestamp}
${dateScope}/${AWS_REGION}/$awsService/aws4_request
${hashedRequest}"

  # Sign data
  local signature=$(sign "${AWS_SECRET_ACCESS_KEY}" "${dateScope}" "${AWS_REGION}" \
                   "${awsService}" "${stringToSign}")

  local authorizationHeader="AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${dateScope}/${AWS_REGION}/${awsService}/aws4_request, SignedHeaders=${headerList}, Signature=${signature}"
  cmd+=("-H" "Authorization: ${authorizationHeader}")

  cmd+=("${requestPath}")

  # Curl
  if [[ ${VERBOSE} == true ]]; then
    echo "${cmd[@]}"
  fi
  "${cmd[@]}"
}
