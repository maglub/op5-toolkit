#!/usr/bin/ruby
#============================================
# Script: monitor.rb
# Author: Magnus Luebeck, magnus.luebeck@kmggroup.ch
# Date:   2014-05-19
#
# Description: This script will connect to the OP5 api and report on services and hosts 
#
# Copyright 2014 KMG Group GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#============================================

require 'net/http'
%w[ rubygems getoptlong yaml pp json open-uri].each { |f| require f }


begin
#------------------------------------------------------------------------
# Definitions:
#
# Actions: command line parameters stating an action:
#
#  --list-changes
#  --commit-changes
#  --rollback-changes
#  --create
#  --delete
#  --change
#  --list (default action)
#
# Object type
#
#  --type=<object type> or -t <object type>
#      host
#      hostgroup
#      hostgroupservice
#      service
#      servicegroup
#      contact
#      contactgroup
#
# Object identification
#
#  --name=<object name> or -n <object name>
#
# Options
#
#  --json='<json string>'   -  If you need to send a full JSON string to, for example, --create
#  --option="key=value"     -  Note, only a few known keywords (i.e. groups) will translate to
#                              an array, even if normally required. For complex options, use --json 
#                           
#  --address=<ip or address>
#  --alias=<alias>
#  --description=<description>  - I.e. service description, which equals to --name if -t service is used
#
#------------------------------------------------------------------------
end

#============================================
# Predefined variables 
#============================================
configDir = File.expand_path(File.dirname(__FILE__) )
configFile = File.expand_path(configDir + '/config.yml')

$logDir   = File.expand_path(File.dirname(__FILE__) + "/log" )
$logFile  = File.open( $logDir + "/monitor.log", 'a') 
#============================================
# Global variables
#============================================

$op5Url                 = nil
$commentColumns         = "comment,service.description,host.name"
$contactColumns         = "name,alias,email"
$contactgroupColumns    = "name,alias,members"
$hostColumns            = "name,alias,address,state"
$hostgroupColumns       = "name,alias,members"
$serviceColumns         = "description,state,host.name,groups"
$servicegroupColumns     = "name,alias,members"

OBJECT_TYPE_HOST         = "hosts"
OBJECT_TYPE_HOSTGROUP    = "hostgroups"
OBJECT_TYPE_SERVICE      = "services"
OBJECT_TYPE_SERVICEGROUP = "servicegroups"
OBJECT_TYPE_CONTACT      = "contacts"
OBJECT_TYPE_CONTACTGROUP = "contactgroups"


$allColumns = {
  OBJECT_TYPE_HOST         => $hostColumns,
  OBJECT_TYPE_HOSTGROUP    => $hostgroupColumns,
  OBJECT_TYPE_CONTACT      => $contactColumns,
  OBJECT_TYPE_CONTACTGROUP => $contactgroupColumns,
  OBJECT_TYPE_SERVICE      => $serviceColumns,
  OBJECT_TYPE_SERVICEGROUP => $servicegroupColumns
}

DEBUG   = 2
VERBOSE = 1
NORMAL  = 0

$debug = false
$writeToLogfile = false
$verboseLevel = 0

optAction         = "list"
optType           = OBJECT_TYPE_HOST
op5User           = nil
op5Password       = nil
optObjectFilter   = {}
optJSON           = nil

#============================================
# functions
#============================================

def op5ListChanges()
  uriEncoded=URI.encode($op5Url + "/api/config/change?format=json")
  uri = URI.parse(uriEncoded)

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Get.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )
  
  response = http.request(request)
  res=JSON.parse(response.body)

  res.each do |change|
    puts "Type: #{change["type"]} #{change["object_type"]} -> Name: #{change["name"]}  (#{change["user"]} at #{change["timestamp"]})"
  end
  
  return 0
end

def op5CommitChanges()
  uriEncoded=URI.encode($op5Url + "/api/config/change?format=json")
  uri = URI.parse(uriEncoded)

  #pp uri
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Post.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )
  
  response = http.request(request)
  puts response.body
  
  return 0
end

def op5RollbackChanges()
  uriEncoded=URI.encode($op5Url + "/api/config/change?format=json")
  uri = URI.parse(uriEncoded)

  #pp uri
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Delete.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )
  
  response = http.request(request)
  puts response.body

  return 0
end

#-------------------------------------------------------------------
# logIt, helper method to print verbose/debug information
#        to the screen and optionally to a log file
#-------------------------------------------------------------------
def logIt(message, *levelOptional)
  level = (levelOptional[0].nil?) ? 0 : levelOptional[0]
  $stderr.puts "#{message}" if level <= $verboseLevel
  ts=Time.now().strftime("%Y-%m-%d %H:%M:%S %Z")
  $logFile.puts(Process.pid.to_s + ";" + ts + ";" + level.to_s + ";" + message) if ($writeToLogfile)
end

#-------------------------------------------------------------------
# thisMethod, helper method to print the method name when debugging
#-------------------------------------------------------------------
def thisMethod()
  caller[0]=~/`(.*?)'/  # note the first quote is a backtick
  $1
end

#-------------------------------------------------------------------
# usageShort - minimal help page
#-------------------------------------------------------------------
def usageShort()
  puts <<EOT
  
  Usage: #{$0} <ACTION> -t <TYPE> <NOUN> {<OPTIONS>}

  Actions (deployment):    [ --list-changes | --commit-changes | --rollback-changes ]
  Actions (configuration): [ --list (default) | --create | --delete | --patch ]

  --type=<objectType>| -t <objectType>:   objectType: { host | hostgroup | contact | contactgroup | service | servicegroup }
  Simplify your use of this command by keeping your credentials in config.yml. For full help, use option --help

  Example: ./monitor.rb --t host   (will list all hosts, since the default action is --list)

EOT
end

#-------------------------------------------------------------------
# usage - minimal help page + examples
#-------------------------------------------------------------------
def usage()
  usageShort
  puts <<EOT

  * List all hosts                       -  #{$0} -t host
  * List all services                    -  #{$0} -t service
  * List all services for one host:      -  #{$0} -t service --host="<hostname>"
  * List all services named "SSH"        -  #{$0} -t service --service=SSH

  Query (--query="<query>"):

  If a query has a result set (hits), the return code is 0, otherwise 1. The queries are based on the OP5 filters, where the type will be passed as the output format, i.e. [services] or [hosts]

  * List acknowledged services            -  #{$0} -t service --query="acknowledged != 0"
  * List services containing "l0" or "L0" -         -  #{$0} -t service --query='description ~~ "l0"'

  * List service comments that are acknowledged, and parse the output for Service Now incidents
  
    #{$0} -t service-comment --acknowledged | sed -e 's!\\([iI][nN][cC][0-9]*\\)!<a href="https://<snow url>/nav_to.do?uri=incident.do?sysparm_query=number=\\1">\\1</a>!g'

  * List services in unacknowledged services in Warning/Critical state, that is not scheduled for downtime (identical to a default view in the web gui)
  
    #{$0} -t service --query="host.scheduled_downtime_depth = 0 and ((state != 0 and acknowledged = 0 and scheduled_downtime_depth = 0) or (host.state != 0 and host.acknowledged = 0))"
  
  * Check if a host or services exists    - The result code is 0 if the host exists, otherwise 1
  
    #{$0} -t host --host=monitor > /dev/null ; echo $?

  Other hints:

  * Use another config file than default (config.yml)

    #{$0} --config=/path/to/my/config/file.yml
  
  For an overview of query parameters, refer to https://kb.op5.com/display/GUI/Listview+filter+columns 

  * Create a host named kmg-test003ec2, with a couple of custom variables, and put it into hostgroup ec2-linux-std:

  ./monitor.rb -t host --create --options='host_name=kmg-test003ec2,alias=win-test003ec2,address=127.0.0.1,_EC2_ID=i-dab2b385,hostgroups=ec2-linux-std,_EC2_REGION=us-west-1'


EOT
end

def op5DoFilterRequest(type, query)
  logIt("* Entering: #{thisMethod()}", DEBUG)
  logIt("  - type: #{type} query: #{query}", DEBUG)
  
  columns = $allColumns[type]
  
  thisQuery = "[#{type}]#{query}&columns=#{columns}"
  logIt("  - query: #{thisQuery}",DEBUG)

  uriEncoded = URI.encode($op5Url + "/api/filter/query?format=json&query=#{thisQuery}&limit=10000000")
  $stderr.puts "URI: #{uriEncoded}" if $debug

  uri = URI.parse(uriEncoded)

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Get.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )

  response = http.request(request)
  res=JSON.parse(response.body)

  return res
  
end #--- end of op5DoFilterRequest

#--------------------------------------------------
# host functions
#--------------------------------------------------

def op5GetHostComments(host)
  res = op5DoFilterRequest("comments", 'is_service = 0 and host.name = "' + host + '"')
  return res
end

def op5GetAllHosts()
  logIt("* Entering: #{thisMethod()}", DEBUG)
  res = op5DoFilterRequest(OBJECT_TYPE_HOST, "all")
  return res
end

def op5GetHost(host)
  logIt("Looking for host: #{host}",DEBUG)
  res = op5DoFilterRequest(OBJECT_TYPE_HOST, 'name ="' +host +'"')
  return res
end

#--------------------------------------------------
# hostgroup functions
#--------------------------------------------------

def op5GetAllHostgroups()
  logIt("* Entering: #{thisMethod()}", DEBUG)
  res = op5DoFilterRequest(OBJECT_TYPE_HOSTGROUP, "all")
  return res
end

#--------------------------------------------------
# service functions
#--------------------------------------------------

def op5GetAllServices()
  logIt("* Entering: #{thisMethod()}", DEBUG)
  res = op5DoFilterRequest(OBJECT_TYPE_SERVICE, "all")
  return res
end

#--------------------------------------------------
# servicegroup functions
#--------------------------------------------------

def op5GetAllServicegroups()
  logIt("* Entering: #{thisMethod()}", DEBUG)
  res = op5DoFilterRequest(OBJECT_TYPE_SERVICEGROUP, "all")
  return res
end

#--------------------------------------------------
# contact functions
#--------------------------------------------------

def op5GetAllContacts()
  logIt("* Entering: #{thisMethod()}", DEBUG)
  contacts = op5DoFilterRequest(OBJECT_TYPE_CONTACT, "all")
  
  contacts.each do | contact |
    contact["contactgroups"] = []
    contact["contactgroups"] << op5GetContactgropusByMember(contact["name"])
  end
  return contacts
end

def op5GetContactsByQuery(query)
  logIt("* Entering: #{thisMethod()}", DEBUG)
  contacts = op5DoFilterRequest(OBJECT_TYPE_CONTACT, query)

  contacts.each do | contact |
    contact["contactgroups"] = []
    contact["contactgroups"] << op5GetContactgropusByMember(contact["name"])
  end
  return contacts
end

#--------------------------------------------------
# contactgroup functions
#--------------------------------------------------

def op5GetAllContactgroups()
  logIt("* Entering: #{thisMethod()}", DEBUG)
  res = op5DoFilterRequest(OBJECT_TYPE_CONTACTGROUP, "all")
  return res
end

def op5GetContactgropusByMember(member)
  contactgroups = []
  contactgroups = op5DoFilterRequest("contactgroups", 'members >= "' + member + '"')
  return contactgroups  
end

#-------------------------------------------------------------------
# op5DeleteObjects() - wrapper method for deleting multiple objects
#-------------------------------------------------------------------
def op5DeleteObjects(type,objects)
  logIt("* Entering: #{thisMethod()}", DEBUG)
  
  objects.each do |object|
    op5DeleteObject(type, object["name"])
  end
end

def op5DeleteObject(type, name)
  logIt("* Entering: #{thisMethod()}", DEBUG)
  
  type = type.gsub(/s$/, '')
  
  if (name.nil? || name == "")
    logIt("Error: no object name passed.", DEBUG)
    return 1
  end

  logIt("  - Preparing to delete #{type} named #{name}", DEBUG)
  uriEncoded=URI.encode($op5Url + "/api/config/#{type}/#{name}?format=json")
  uri = URI.parse(uriEncoded)

  #pp uri
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Delete.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )
  
  response = http.request(request)
  puts response.body

  return 0

end

#-------------------------------------------------------------------
# op5PrintObjects() - wrapper method for listing objects
#-------------------------------------------------------------------
def op5PrintObjects(type,objects)
  logIt("* Entering: #{thisMethod()}", DEBUG)
  
  objects.each do |object|
    case type
    when OBJECT_TYPE_HOST
      printf "name: %-25s alias: %-40s address: %-15s state: %i\n", object["name"], object["alias"], object["address"], object["state"] if (! object["name"].nil?)
    when OBJECT_TYPE_HOSTGROUP, OBJECT_TYPE_CONTACTGROUP, OBJECT_TYPE_SERVICEGROUP

      printf "name: %-25s alias: %-40s members: ", object["name"], object["alias"] if (! object["name"].nil?)
      printCount=0
      object["members"].each do | member |
        printf "," if printCount > 0
        printf "%s", (member.class.to_s == "Array") ?  member[0] + ";" + member[1] : member
        printCount += 1
      end
      printf "\n"
      
    when OBJECT_TYPE_SERVICE
      printf "host_name: %-25s description: %-40s\n", object["host"]["name"], object["description"] if (! object["description"].nil?)
    when OBJECT_TYPE_CONTACT
      printf "name: %-25s alias: %-30s email: %-35s contactgroups: ", object["name"], object["alias"], object["email"] if (! object["name"].nil?)

      printCount=0
      object["contactgroups"].each do |contactgroup|
        printf "," if printCount > 0
        printf "%s", contactgroup[0]["name"]
        printCount += 1
      end
      printf "\n"
    end
  end
end

def op5GetAllObjectsByType(type)
  logIt("* Entering: #{thisMethod()}", DEBUG)
  res = {}
  
  case type
    when OBJECT_TYPE_HOST         ; res = op5GetAllHosts()
    when OBJECT_TYPE_HOSTGROUP    ; res = op5GetAllHostgroups()
    when OBJECT_TYPE_SERVICE      ; res = op5GetAllServices()
    when OBJECT_TYPE_SERVICEGROUP ; res = op5GetAllServicegroups()
    when OBJECT_TYPE_CONTACT      ; res = op5GetAllContacts()
    when OBJECT_TYPE_CONTACTGROUP ; res = op5GetAllContactgroups()
  end
  
  return res
end

def op5GetObjectsByQuery(type, query)
  logIt("* Entering: #{thisMethod()}", DEBUG)
  res = {}
  
  #--- exceptions, when not enough information is returned (i.e. the contacts does not return the members of the contact group)
  case type
    when OBJECT_TYPE_CONTACT
      res = op5GetContactsByQuery(query)
    else
      res = op5DoFilterRequest(type, query)
    end
  
  return res
  
end


def getQueryStringByType(type, objectFilter = {})
  
  
  #--------------------------------------
  # translation definitions
  #--------------------------------------
  
  translateTable = {
    "services" => {
      :alias  => "alias",
      :name   => "description",
      :host   => "host.name"
    },
    "hosts" => {
      :alias  => "alias",
      :name => "name",
      :host => "name"
    },
    "hostgroups" => {
      :alias  => "alias",
      :name => "name"
    },
    "contacts" => {
      :alias  => "alias",
      :name => "name"      
    },
    "contactgroups" => {
      :alias  => "alias",
      :name => "name"      
    }
  }
  
  thisQuery = ""
  
  predicateCount = 0
  objectFilter.each do | snippet |
    logIt("  - snippet: #{snippet}", DEBUG)
    
    thisQuery += " and " if (predicateCount > 0)
    thisQuery += translateTable[type][snippet[0]] + ' = "' + snippet[1].to_s + '"'

    predicateCount += 1
  end

  thisQuery = "all" if (thisQuery == "")
  return thisQuery
end


def op5ListObjects(type, objectFilter = {})
  logIt("* Entering: #{thisMethod()}", DEBUG)
  logIt("  - objectFilter: " + objectFilter.inspect, DEBUG)

  res = {}

  if (objectFilter[:query].nil?)
    objectFilter[:query] = getQueryStringByType(type, objectFilter)
    logIt("  - parsedQuery: " + objectFilter[:query], DEBUG)
  end
  
  
  if ( objectFilter == {})
    res = op5GetAllObjectsByType(type)
  elsif (!objectFilter[:query].nil?)
    logIt("type: #{type} query: #{objectFilter[:query]}", DEBUG)
    res = op5GetObjectsByQuery(type, objectFilter[:query])
    #op5DoFilterRequest(type, objectFilter[:query])
  end
    
 return res
end

def getObjectType(type)
  logIt("* Entering: #{thisMethod()}", DEBUG)

  res = nil
  
  case type
    when 'host','hosts'                   ; res = OBJECT_TYPE_HOST
    when 'hostgroup','hostgroups'         ; res = OBJECT_TYPE_HOSTGROUP
    when 'contact', 'contacts'            ; res = OBJECT_TYPE_CONTACT
    when 'contactgroup', 'contactgroups'  ; res = OBJECT_TYPE_CONTACTGROUP
    when 'service', 'services'            ; res = OBJECT_TYPE_SERVICE 
    when 'servicegroup', 'servicegroups'  ; res = OBJECT_TYPE_SERVICEGROUP
  end
  
  logIt("  - type: #{res}", DEBUG)
  return res
end

#============================================
#============================================
# MAIN
#============================================
#============================================

opts = GetoptLong.new
opts.quiet = true

#-----------------------------
# define options
#-----------------------------
begin
opts.set_options(
  [ "--help-short", "-h", GetoptLong::NO_ARGUMENT],
  [ "--help",             GetoptLong::NO_ARGUMENT],
  [ "--debug",            GetoptLong::NO_ARGUMENT],
  [ "--verbose", "-v",    GetoptLong::OPTIONAL_ARGUMENT],
  
  #--- credentials and configuration
  [ "--user", "-u",       GetoptLong::OPTIONAL_ARGUMENT],
  [ "--password", "-p",   GetoptLong::OPTIONAL_ARGUMENT],
  [ "--url",              GetoptLong::OPTIONAL_ARGUMENT],
  [ "--config", "-C",     GetoptLong::OPTIONAL_ARGUMENT],

  #--- actions -> deployment
  [ "--list-changes",     GetoptLong::NO_ARGUMENT],
  [ "--rollback-changes", GetoptLong::NO_ARGUMENT],
  [ "--commit-changes",   GetoptLong::NO_ARGUMENT],

  #--- actions -> configuration
  [ "--create",           GetoptLong::OPTIONAL_ARGUMENT],
  [ "--delete",           GetoptLong::OPTIONAL_ARGUMENT],
    
  #--- options
  [ "--type", "-t",       GetoptLong::OPTIONAL_ARGUMENT],

  #--- options - objectFilters
  [ "--address",          GetoptLong::OPTIONAL_ARGUMENT],
  [ "--alias",            GetoptLong::OPTIONAL_ARGUMENT],
  [ "--name", "-n",       GetoptLong::OPTIONAL_ARGUMENT],
  [ "--host", "-H",       GetoptLong::OPTIONAL_ARGUMENT],
  [ "--options",          GetoptLong::OPTIONAL_ARGUMENT],  

  #--- extra features
  [ "--json",             GetoptLong::OPTIONAL_ARGUMENT],  
  [ "--query", "-Q",      GetoptLong::OPTIONAL_ARGUMENT],
  [ "--with-comments",    GetoptLong::NO_ARGUMENT],
  [ "--acknowledged",     GetoptLong::NO_ARGUMENT],
  [ "--get-config",       GetoptLong::NO_ARGUMENT],
)
end
#-----------------------------
# parsing options
#-----------------------------

begin
  opts.each do |opt, arg|
    case opt
      when '--help'             ; usage();      exit 0
      when '--help-short'       ; usageShort(); exit 0
      when '--debug'            ; $writeToLogfile = true ; $verboseLevel = DEBUG
      
      #--- deployment actions
      when '--list-changes'     ; optAction = "list-changes"
      when '--rollback-changes' ; optAction = "rollback-changes"
      when '--commit-changes'   ; optAction = "commit-changes"
      
      #--- configuration actions
      when '--list'             ; optAction = "list"
      when '--create'           ; optAction = "create"
      when '--patch'            ; optAction = "patch"
      when '--delete'           ; optAction = "delete"
        
      #--- object type
      when '--type'             ; optType         = getObjectType(arg)

      #-- object filters
      when '--alias'            ; optObjectFilter[:alias]        = arg
      when '--name'             ; optObjectFilter[:name]         = arg
      when '--host'             ; optObjectFilter[:host        ] = arg
      when '--hostgroup'        ; optObjectFilter[:hostgroup   ] = arg
      when '--service'          ; optObjectFilter[:service     ] = arg
      when '--servicegroup'     ; optObjectFilter[:servicegroup] = arg
      when '--contact'          ; optObjectFilter[:contact     ] = arg
      when '--contactgroup'     ; optObjectFilter[:contactgroup] = arg
      when '--query'            ; optObjectFilter[:query]        = arg

      #--- extra features
      when '--json'             ; optJSON = arg
    end
  end
rescue Exception => e
  usageShort unless e.to_s == "exit"
  exit 0
end

#-----------------------------
# Config file (yml)
#-----------------------------

begin
  if File.exist?(configFile)
    config = YAML.load(File.read(configFile))
  
    #--- set default config for AWS (i.e. access key, secret key, region, http proxy in config["aws"])
  #  AWS.config(config["aws"])
  
    #--- set default config for this app (in config["app"])
    $op5Url = config["op5"]["url"].nil? ? nil : config["op5"]["url"]
    $op5User = op5User.nil? ? config["op5"]["userName"] : op5User
    $op5Password = op5Password.nil? ? config["op5"]["password"] : op5Password
    
  else
    puts "WARNING: #{configFile} does not exist"
  end
end

#-----------------------------
# Actions
#-----------------------------

logIt("* Starting #{$0} - type: #{optType}",DEBUG)


case optAction
when 'list-changes'
  op5ListChanges()
  exit 0
when 'rollback-changes'
  op5RollbackChanges()
  exit 0
when 'commit-changes'
  op5CommitChanges()
  exit 0
when 'list'
  objects = op5ListObjects(optType,optObjectFilter)
  op5PrintObjects(optType, objects)
when 'create'
when 'patch'
when 'delete'
  objects = op5ListObjects(optType,optObjectFilter)
  op5DeleteObjects(optType, objects )
else
  logIt("ERROR: No valid action selected.", NORMAL)
  exit 1
end

