#
# bulkorigin.R - perform bulk IP to ASN mapping via Team Cymru whois service
#
# Author: @hrbrmstr
# Version: 0.1
# Date: 2013-02-07
#
# Copyright 2013 Bob Rudis
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#   
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.#
 
library(plyr)
 
# short function to trim leading/trailing whitespace
trim <- function (x) gsub("^\\s+|\\s+$", "", x)
 
BulkOrigin <- function(ip.list,host="v4.whois.cymru.com",port=43) {
 
  # Retrieves BGP Origin ASN info for a list of IP addresses
  #
  # NOTE: IPv4 version
  #
  # NOTE: The Team Cymru's service is NOT a GeoIP service!
  # Do not use this function for that as your results will not
  # be accurate.
  #
  # Args:
  #   ip.list : character vector of IP addresses
  #   host: which server to hit for lookup (defaults to Team Cymru's server)
  #   post: TCP port to use (defaults to 43)
  #
  # Returns:
  #   data frame of BGP Origin ASN lookup results
 
 
  # setup query
  cmd = "begin\nverbose\n" 
  ips = paste(unlist(ip.list), collapse="\n")
  cmd = sprintf("%s%s\nend\n",cmd,ips)
 
  # setup connection and post query
  con = socketConnection(host=host,port=port,blocking=TRUE,open="r+")  
  cat(cmd,file=con)
  response = readLines(con)
  close(con)
 
  # trim header, split fields and convert results
  response = response[2:length(response)]
  response = lapply(response,function(n) {
    sapply(strsplit(n,"|",fixed=TRUE),trim)
  })  
  response = adply(response,c(1))
  response = response[,2:length(response)]
  names(response) = c("AS","IP","BGP.Prefix","CC","Registry","Allocated","AS.Name")
 
  return(response)
 
}
 
BulkPeer <- function(ip.list,host="v4-peer.whois.cymru.com",port=43) {
 
  # Retrieves BGP Peer ASN info for a list of IP addresses
  #
  # NOTE: IPv4 version
  #
  # NOTE: The Team Cymru's service is NOT a GeoIP service!
  # Do not use this function for that as your results will not
  # be accurate.
  #
  # Args:
  #   ip.list : character vector of IP addresses
  #   host: which server to hit for lookup (defaults to Team Cymru's server)
  #   post: TCP port to use (defaults to 43)
  #
  # Returns:
  #   data frame of BGP Peer ASN lookup results
 
 
  # setup query
  cmd = "begin\nverbose\n" 
  ips = paste(unlist(ip.list), collapse="\n")
  cmd = sprintf("%s%s\nend\n",cmd,ips)
 
  # setup connection and post query
  con = socketConnection(host=host,port=port,blocking=TRUE,open="r+")  
  cat(cmd,file=con)
  response = readLines(con)
  close(con)
 
  # trim header, split fields and convert results
  response = response[2:length(response)]
  response = lapply(response,function(n) {
    sapply(strsplit(n,"|",fixed=TRUE),trim)
  })  
  response = adply(response,c(1))
  response = response[,2:length(response)]
  names(response) = c("Peer.AS","IP","BGP.Prefix","CC","Registry","Allocated","Peer.AS.Name")
  return(response)
 
}
