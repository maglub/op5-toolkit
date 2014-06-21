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


#============================================
# Predefined variables 
#============================================
configDir = File.expand_path(File.dirname(__FILE__) )
configFile = File.expand_path(configDir + '/config.yml')

op5Url        = nil
op5User       = nil
op5Password   = nil
op5Type       = nil
op5NameColumn = nil
optHost       = nil
optOptions    = nil
optContact    = nil
optGroup      = nil

#$servicesColumns = "description,state,host.alias"
$serviceColumns   = "description,state,host.name,groups"
$hostColumns      = "name,alias,address,state"
$commentColumns   = "comment,service.description,host.name"
$contactColumns   = "name,alias,email"

$debug = false

optAcknowledged=false
optAction = "list"

#============================================
# Functions
#============================================
def usage
  puts <<EOT
Usage: #{$0} [-v]
  --help, -h:                              This Help
  --config, -c:                            Use config file (default config.yml in the same directory as this script)
  --type, -t:                              Type [host|service|service-comment|host-comment]
  --host, -H:                              Specify host name
  --service, -H:                           Specify service name
  --degug, -v:                             Output debug information
  --service-comment {--acknowledged}:      Service comments (--acknowledged, only non OK and ack:ed services are shown)
  --create
  --list-changes
  --commit-changes
  --rollback-changes
  --options = "host_name=apa,alias=bepa"
Example:

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

#----------------------------------------
# op5DoFilterRequest
#----------------------------------------

def op5DoFilterRequest(type, query, columns)
  
  thisQuery = "[#{type}]#{query}&columns=#{columns}"
  $stderr.puts "Query: #{thisQuery}" if $debug

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

def op5DoConfigRequest(objectType, objectName)
  
  #thisQuery = "[#{type}]#{query}&columns=#{columns}"
  #$stderr.puts "Query: #{thisQuery}" if $debug

  uriEncoded = URI.encode($op5Url + "/api/config/#{objectType}/#{objectName}?format=json&limit=10000000")
  $stderr.puts "URI: #{uriEncoded}" if $debug

  uri = URI.parse(uriEncoded)

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Get.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )

  response = http.request(request)
  res=JSON.parse(response.body)

  res = res.inject({}){|memo,(k,v)| memo[k.to_sym] = v; memo}

  result = []
  #pp res[:services]
  res[:services].each do | service |
    result << {:service_description => service["service_description"]}
    puts "#{objectName};#{service["service_description"]}"
  end
  return res
  
end #--- end of op5DoFilterRequest

def op5GetAllHostgroups()
  uriEncoded = URI.encode($op5Url + "/api/config/hostgroup?format=json&limit=10000000")
  $stderr.puts "URI: #{uriEncoded}" if $debug

  uri = URI.parse(uriEncoded)

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Get.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )

  response = http.request(request)
  res=JSON.parse(response.body)

#  res = res.inject({}){|memo,(k,v)| memo[k.to_sym] = v; memo}

  return res
  
  result = []
  #pp res[:services]
  res[:services].each do | service |
    result << {:service_description => service["service_description"]}
    puts "#{objectName};#{service["service_description"]}"
  end
  return res
end

def op5PrintAllHostgroups()
  res = op5GetAllHostgroups
  res.each do |hostgroup|
    puts "#{hostgroup["name"]}"
  end
end

def op5GetHostgroupServices(hostgroup)
  uriEncoded = URI.encode($op5Url + "/api/config/hostgroup/#{hostgroup}?format=json&limit=10000000")
  $stderr.puts "URI: #{uriEncoded}" if $debug

  uri = URI.parse(uriEncoded)

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Get.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )

  response = http.request(request)
  res=JSON.parse(response.body)

#  res = res.inject({}){|memo,(k,v)| memo[k.to_sym] = v; memo}

  return res
end

def op5GetAllHostgroupServices()
  res = op5GetAllHostgroups
  
  resArray = []
  res.each do |hostgroup|
    res2 = op5GetHostgroupServices(hostgroup["name"])
    if (!res2["services"].nil?)
      res2["services"].each do |hostgroupservice|
        puts "#{hostgroup["name"]};#{hostgroupservice["service_description"]}" if $debug
        resArray << {:name => hostgroup["name"], :service_description => hostgroupservice["service_description"]}
      end
    end
#    puts "#{hostgroup["name"]}"
  end
  return resArray
end

def op5PrintAllHostgroupServices()
  res = op5GetAllHostgroupServices()
  res.each do |hostgroupService|
    puts "#{hostgroupService[:name]};#{hostgroupService[:service_description]}"
  end
end

def op5PrintHostgroupServices(hostgroup)
  res = op5GetHostgroupServices(hostgroup)
  res.each do |hostgroupService|
    puts "#{hostgroup};#{hostgroupservice["service_description"]}"
  end
 
end
def op5DoCreate(type, name, jsonString)
  uriEncoded = URI.encode($op5Url + "/api/config/#{type}/#{hostName}")
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

end

#----------------------------------------
# op5GetHostConfig
#----------------------------------------
def op5GetHostConfig(hostName)
  
  $stderr.puts "  - Getting host config" if $debug
  uriEncoded = URI.encode($op5Url + "/api/config/host/#{hostName}?format=json")
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

end

#----------------------------------------
# op5ServiceExists
#----------------------------------------
def op5ServiceExists(hostName, serviceName)

  name = hostName + ";" + serviceName
  
  uriEncoded=URI.encode($op5Url + "/api/status/service/#{name}?format=json")
  uri = URI.parse(usiEncoded)

  #pp uri
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Get.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )

  response = http.request(request)
  res=JSON.parse(response.body)

  return res
end #--- end of op5ServiceExists

#----------------------------------------
# op5ServiceExists
#----------------------------------------

def op5ServiceExists
  res = op5DoFilterRequest("hosts", "all", "name")
  return res
end #--- end of op5ServiceExists

#----------------------------------------
#
#----------------------------------------

def op5GetAllServices()
  $stderr.puts "Getting all services" if $debug
  res = op5DoFilterRequest("services", "all", $serviceColumns)
  return res
end

def op5GetHostServices(filter)
  res = op5DoFilterRequest("services", filter, $serviceColumns)  
  return res
end

def op5GetService(host, service)
  query = ""
  
  if (host != "all")
    query = 'host.name = "' + host + '"'
  end
    
  if (service != "all")
    #--- if the query is empty (no host), there is no need for "and"
    query = (query == "" ) ? 'description = "' + service + '"' : query + ' and description = "' + service + '"'
  end
  
  res = op5DoFilterRequest("services", query, $serviceColumns)
  return res
end

def op5GetGroupService(group, service)
  query = ""
  
  if (group != "all")
    query = 'groups ~ "' + group + '"'
  end
    
  if (service != "all")
    #--- if the query is empty (no host), there is no need for "and"
    query = (query == "" ) ? 'description = "' + service + '"' : query + ' and description = "' + service + '"'
  end

  pp query
  exit 0
  
  res = op5DoFilterRequest("services", query, $serviceColumns)
  pp res if $debug
  return res
end

def op5GetQuery(query)
  res = op5DoFilterRequest("services", host + " and " + service, $serviceColumns+$op5ExtraColumns)
  return res  
end

def op5GetServiceComments(host, service)
  res = op5DoFilterRequest("comments", 'is_service = 1 and host.name = "' + host + '" and service.description = "' + service + '"' , "comment,entry_time,expire_time,service.acknowledged,entry_type")
  return res
end

#--------------------------------------------------
# common functions
#--------------------------------------------------

def op5DeleteObject(type, name)
  $stderr.puts "* Entering: #{thisMethod()}" if $debug 
  
  if (name.nil? || name == "")
    $stderr.puts "Error: no object name passed: #{options.inspect}"
    return 1
  end
  
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

#--------------------------------------------------
# contact functions
#--------------------------------------------------

def op5GetAllContacts()
  res = op5DoFilterRequest("contacts", "all", $contactColumns)
  return res
end

def op5PrintAllContacts()
  $stderr.puts "* Entering: #{thisMethod()}" if $debug 
  
  op5GetAllContacts.each do |contact|
    puts "#{contact["name"]}"
  end
  return 0
end

def op5DeleteContact(options)
  $stderr.puts "* Entering: #{thisMethod()}" if $debug 

  op5DeleteObject("contact", options[:name])

  return 0

end

#--------------------------------------------------
# host functions
#--------------------------------------------------
def op5GetHostComments(host)
  res = op5DoFilterRequest("comments", 'is_service = 0 and host.name = "' + host + '"' , "comment,entry_time,expire_time,host.acknowledged")
  return res
end

def op5GetAllHosts()
  res = op5DoFilterRequest("hosts", "all", $hostColumns)
  return res
end

def op5GetHost(host)
  puts "Looking for host: #{host}" if $debug
  res = op5DoFilterRequest("hosts", 'name ="' +host +'"', $hostColumns)
  return res
end

def op5CreateHost(options = nil)
  
  if (options.nil?)
    $stderr.puts "Error: no options passed: #{options.inspect}"
    return 1
  end
  
  optionsHash = {}  
  options.each do |hash, value|
    optionsHash[hash] = value
  end

  if (optionsHash[:template].nil?)
    optionsHash[:template] = "default-host-template"
  end
  
  optionsJSON = optionsHash.to_json
  
  $stderr.puts "  - optionsHash = #{optionsHash.inspect}" if $debug
  $stderr.puts "  - optionsJSON = #{optionsJSON}" if $debug
  
  uriEncoded=URI.encode($op5Url + "/api/config/host")
  uri = URI.parse(uriEncoded)

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE

  request = Net::HTTP::Post.new(uri.request_uri)
  request.basic_auth($op5User, $op5Password )
  request.add_field("content-type","application/json")
  #request.set_form_data(optionsHash)
  request.body = optionsHash.to_json
  
  response = http.request(request)
  res=JSON.parse(response.body)
  
  if (response.code.to_i == 201)
    $stderr.puts "OK: created #{optionsHash[:host_name]}"
  else
    $stderr.puts "Error: #{res["error"]}"
  end
  
  return 0
end


def op5DeleteHost(name)
  $stderr.puts "* Entering: #{thisMethod()}" if $debug 
  op5DeleteObject("host", name)
  return 0
end

def listOP5Changes()
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

def commitOP5Changes()
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

def rollbackOP5Changes()
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

def hashifyString(string)
  hash = {}
  string.split(/,/).each do |token|
    name, value = token.split(/=/)
    case name
    when 'hostgroups'
      hash[name] = [value]
    else
      hash[name] = value
    end
  end
  hash = hash.inject({}){|memo,(k,v)| memo[k.to_sym] = v; memo}
  
  pp hash if $debug
  return hash
end

#-------------------------------------------------------------------
# thisMethod, helper method to print the method name when debugging
#-------------------------------------------------------------------
def thisMethod
  caller[0]=~/`(.*?)'/  # note the first quote is a backtick
  $1
end

#============================================
# Parse options
#============================================
if (ARGV.length == 0 )
  usage
  exit 0
end

opts = GetoptLong.new
opts.quiet = true

opts.set_options(
  [ "--help", "-h", GetoptLong::NO_ARGUMENT],
  [ "--debug", "-v", GetoptLong::NO_ARGUMENT],
  [ "--user", "-u", GetoptLong::OPTIONAL_ARGUMENT],
  [ "--password", "-p", GetoptLong::OPTIONAL_ARGUMENT],
  [ "--type", "-t", GetoptLong::OPTIONAL_ARGUMENT],
  [ "--host", "-H", GetoptLong::OPTIONAL_ARGUMENT],
  [ "--service", "-S", GetoptLong::OPTIONAL_ARGUMENT],
  [ "--query", "-Q", GetoptLong::OPTIONAL_ARGUMENT],
  [ "--with-comments", GetoptLong::NO_ARGUMENT],
  [ "--acknowledged", GetoptLong::NO_ARGUMENT],
  [ "--config", "-c", GetoptLong::OPTIONAL_ARGUMENT],
  [ "--create", GetoptLong::OPTIONAL_ARGUMENT],
  [ "--delete", GetoptLong::OPTIONAL_ARGUMENT],
  [ "--get-config", GetoptLong::NO_ARGUMENT],
  [ "--list-changes", GetoptLong::NO_ARGUMENT],
  [ "--rollback-changes", GetoptLong::NO_ARGUMENT],
  [ "--commit-changes", GetoptLong::NO_ARGUMENT],
  [ "--options", GetoptLong::OPTIONAL_ARGUMENT],  
  [ "--group", "-G", GetoptLong::OPTIONAL_ARGUMENT],  
  [ "--contact", GetoptLong::OPTIONAL_ARGUMENT]  
)

opts.quiet = true

op5Host="all"
op5Service="all"
op5Query=""
optGetComments = false


begin
opts.each do |opt,arg|
  case opt
    when '--help'
      begin
        usage
        exit 0
      end
    when '--debug'
      $debug = true
    when '--config'
      configFile=arg
    when '--user'
      op5User=arg
    when '--password'
      op5Password=arg 
    when '--type'
      op5Type=arg 
    when '--host'
      op5Host=arg
    when '--service'
          op5Service = arg
    when '--query'
    begin
      op5Query = arg
    end
    when '--with-comments'
      optGetComments = true
    when '--acknowledged'
      optAcknowledged = true
    when '--create'
      optAction = "create"
    when '--get-config'
      optAction = "getConfig"
    when '--list-changes'
      optAction = "review"
    when '--rollback-changes'
      optAction = "rollback"
    when '--commit-changes'
      optAction = "commit"
    when '--delete'
      optAction = "delete"
    when '--options'
      optOptions = arg
    when '--contact'
      optContact = arg
    when '--group'
      optGroup = arg

  end
end
rescue Exception => e
  usage
  exit 1
end


#============================================
# Config file (yml)
#============================================

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

#============================================
# Query types
#============================================

op5Type = op5Type.nil? ? "hosts" : op5Type

case optAction
when 'review'
  listOP5Changes()
  exit 0
when 'rollback'
  rollbackOP5Changes()
  exit 0
when 'commit'
  commitOP5Changes()
  exit 0
end

  
case op5Type
  when 'hosts', 'host'
  begin
    case optAction
      when 'list'
        if ( op5Query != "" )
          res = op5DoFilterRequest("hosts", op5Query, "name")
        elsif (op5Host != "all")
          res = op5GetHost(op5Host)
        else
          res = op5GetAllHosts()
        end
      when 'create'
        if (optOptions.nil?)
          hostOptions = {:host_name => op5Host, :address => "127.0.0.1", :alias => op5Host}
        else
          hostOptions = hashifyString(optOptions)
        end
        
        $stderr.puts "  - Creating new host #{hostOptions[:host_name]}"

        op5CreateHost(hostOptions)
        exit 0
      when 'getConfig'
        pp op5GetHostConfig(op5Host)
        exit 0
       when 'delete'
        op5DeleteHost(op5Host)
        exit 0
    end
  end
  when 'contacts'
  begin
    case optAction
      when 'list'
          op5PrintAllContacts()
          exit 0
      when 'delete'
        op5DeleteContact({:name => optContact})
        exit 0
    end
  end
  when 'service', 'services'
    case optAction
      when 'list'
      begin
        if ( op5Query != "" )
          res = op5DoFilterRequest("services", op5Query, "description,state,host.name")
        elsif (op5Host == "all" && op5Service == "all" && optGroup == nil)
          res = op5GetAllServices()
        elsif (optGroup != "all")
          res = op5DoConfigRequest("hostgroup", optGroup)
          exit 0
        else
          res = op5GetService(op5Host, op5Service)
        end
      end
    end
  when 'hostgroups'
    case optAction
      when 'list'
        op5PrintAllHostgroups()
        exit 0
    end
  when 'hostgroupservices'
  case optAction
    when 'list'
      begin
        if (optGroup == nil && op5Service == "all")
          res = op5PrintAllHostgroupServices()
          exit 0
        elsif (optGroup != "all")
          res = op5DoConfigRequest("hostgroup", optGroup)
          exit 0
        else
          res = op5GetService(op5Host, op5Service)
        end
      end
    end
  when 'service-comments', 'service-comment'
  begin
    case optAcknowledged
      when true
        res = op5DoFilterRequest("comments","type = 2 and service.acknowledged != 0 and service.state != 0 and entry_type = 4", $commentColumns)
      when false
        res = op5DoFilterRequest("comments","type = 2", $commentColumns)
    end  
  end
  when 'host-comments', 'host-comment'
  begin
    case optAcknowledged
      when true
        res = op5DoFilterRequest("comments","type = 1 and service.acknowledged != 0 and service.state != 0 and entry_type = 4", $commentColumns)
      when false
        res = op5DoFilterRequest("comments","type = 1", $commentColumns)
    end  
  end
end


#============================================
# MAIN
#============================================

#https://kb.op5.com/display/GUI/Listview+filter+columns#Listviewfiltercolumns-Services

if (res.count == 0)
  exit 1
end

res.each do |item|
      #  puts "========================================="
      #  pp item
  
  case op5Type
    when 'service', 'services'
    begin
      if (item["host"]["name"])
        puts item["host"]["name"] + ";" + item["description"] + ";State: " + item["state"].to_s
        if (optGetComments == true)
          commentsRes = op5GetServiceComments(item["host"]["name"],item["description"])
          commentsRes.each do "resItem"
            pp commentsRes
          end #--- end commentsRes.each do
        end
      end
    end #--- end when 'service'
        
    when 'service-comment', 'service-comments', 'host-comment', 'host-comments'
    begin
        pp item if $debug
        puts "#{item["host"]["name"]};#{item["service"]["description"]};#{item["comment"]}"
    end #--- end of service-comment
    when 'host', 'hosts'
    begin
      puts "#{item["name"].to_s};#{item["alias"].to_s};#{item["address"].to_s};#{item["state"]}"
      if (optGetComments)
        commentsRes = op5GetHostComments(item["name"])
        commentsRes.each do |resItem|
            pp resItem
        end #--- end commentsRes.each do
      end #--- end of if(optGetComments)
    end #--- end of host

  end #--- end case op5Type
end #--- end res.each do
