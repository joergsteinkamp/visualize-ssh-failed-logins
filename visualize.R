library(scales)
library(grid)
library(RSQLite)
library(rgdal)
library(ggplot2)
library(plyr)

### available here: http://www.r-bloggers.com/retrieve-ip-asn-bgp-peer-info-with-r/
source("~/lib/R/bulkorigin.R")

update_db <- function(dbcon) {
  if (!any(dbListTables(dbcon) == "subnet")) 
    dbSendQuery(dbcon, "CREATE TABLE subnet
         (id INTEGER PRIMARY KEY AUTOINCREMENT,
          subnet TEXT,
          country TEXT)")

  query <- dbSendQuery(dbcon, "SELECT * FROM ip")
  ips   <- dbFetch(query)
  dbClearResult(query)

### update the database with the subnets
  for (i in 1:nrow(ips)) {
   ### doing this for all IP addresses at once caused
   ### trouble, since sometimes 7 or 14 entries were returned 
   ###  These subnets caused the trouble: 1.93.0.0/16, 202.85.212.0/22, 211.99.224.0/19, 59.151.103.0/24
    whois <- as.vector(BulkOrigin(ips$v4[i]))
  
    query <- dbSendQuery(dbcon, paste("SELECT * FROM subnet WHERE subnet='", whois[3], "'", sep=""))
    res   <- dbFetch(query)
    dbClearResult(query)
    if (nrow(res)==0) {
      query <- dbSendQuery(dbcon, paste("INSERT INTO subnet(subnet, country) VALUES('", whois[3],"','",whois[4],"')",sep=""))
      query <- dbSendQuery(dbcon, paste("SELECT * FROM subnet WHERE subnet='", whois[3], "'", sep=""))
      res   <- dbFetch(query)
      dbClearResult(query)
    }
    query <- dbSendQuery(dbcon, paste("UPDATE ip SET subnetid=",res$id," WHERE v4='", ips$v4[i], "'", sep=""))
  }
}
### END function update_db

dbfile <- "failed_ssh_logins.db"
dbcon  <- dbConnect(SQLite(), dbname=dbfile)

### this is only necessary if the db was not yet modified
### check table subnet for pressence
tables <- dbListTables(dbcon)
if (!any(tables=="subnet"))
  update_db(dbcon)

## for ( t in tables) {
##   print(dbListFields(dbcon, t))
## }

### get the data from the database
query   <- dbSendQuery(dbcon, "SELECT * FROM event")
events  <- dbFetch(query)
dummy   <- dbClearResult(query)
message(nrow(events))

query   <- dbSendQuery(dbcon, "SELECT * FROM ip")
ips     <- dbFetch(query)
dummy   <- dbClearResult(query)
message(nrow(ips))

query   <- dbSendQuery(dbcon, "SELECT * FROM user")
users   <- dbFetch(query)
dummy   <- dbClearResult(query)
message(nrow(users))

query   <- dbSendQuery(dbcon, "SELECT * FROM subnet")
subnets <- dbFetch(query)
dummy   <- dbClearResult(query)
message(nrow(subnets))

### update the event data.frame to include a R Date column
### might need adaptation on langer time scales, using a weekly
### or monthly time step
events$RDate = as.Date(strptime(events$date, "%b %d %H:%M:%S %Y"))

### and create a new data.frame containing the events per day
freqs <- aggregate(events$RDate, by=list(events$RDate), FUN=length)
colnames(freqs) <- c("Date", "N")

### visualize, breaks might need apadtation on longer time scales
if (require(cairoDevice)) {
  Cairo_png("ts.png", width=9, height=6)
} else {
  pdf("ts.pdf", paper="special", width=9, height=6)
}
p <- ggplot(freqs, aes(x=Date, y=N))
p <- p + geom_bar(stat="identity", fill="darkblue")
p <- p + scale_x_date(breaks="1 week", labels=date_format("%Y-%m-%d"))
p <- p + theme(axis.text.x = element_text(angle=90))
print(p)
dummy <- dev.off()

### update the username data.frame (kind of table in R) by adding the number a
### username was used
users$N <- NA
for (i in 1:nrow(users)) {
  users$N[i] = nrow(subset(events, userid==users$id[i]))
}

### convert from factor to character if nesseccary
if (is.factor(users$name))
  users$name <- as.character(users$name)

### sort by alphabet first; in reverse order due to axis flipping in ggplot later
users <- users[order(users$name, decreasing = TRUE),]
  
### oder by usage
users$name <- factor(users$name, levels=users$name[order(users$N)])

### visualize
###
### only a subset is displayed (command "subset" within each "ggplot" command).
### This and the width and height options have to be adjusted to each database,
### otherwise to little or to much data is selected and the output graphics 
### are not readable anymore.
###
if (require(cairoDevice)) {
  Cairo_png("user.png", width=9, height=12)
} else {
  pdf("user.pdf", paper="special", width=9, height=12)
}
p <- ggplot(subset(users, name!="" & N>1), aes(x=name, y=N, fill=name))
p <- p + geom_bar(stat = "identity")
p <- p + scale_y_log10()
p <- p + guides(fill=FALSE)
p <- p + coord_flip()
print(p)
dummy <- dev.off()

### do the same for the subnets/countries
### However, a subnetid column has to be
### added to the events data.frame first
events$subnetid <- NA
for (i in 1:nrow(events)) {
  events$subnetid[i] = ips[events$ipid[i],]$subnetid
}

subnets$N <- NA
for (i in 1:nrow(subnets)) {
  subnets$N[i] = nrow(subset(events, subnetid==subnets$id[i]))
}

if (is.factor(subnets$subnet))
  subnets$subnet <- as.character(subnets$subnet)
subnets <- subnets[order(subnets$subnet, decreasing = TRUE),]
subnets$subnet <- factor(subnets$subnet, levels=subnets$subnet[order(subnets$N)])

if (require(cairoDevice)) {
  Cairo_png("subnet.png", width=9, height=9)
} else {
  pdf("subnet.pdf", paper="special", width=9, height=9)
}
p <- ggplot(subset(subnets, N>10), aes(x=subnet, y=N, fill=subnet))
p <- p + geom_bar(stat = "identity")
p <- p + scale_y_log10()
p <- p + guides(fill=FALSE)
p <- p + coord_flip()
print(p)
dummy <- dev.off()

### now for the coutries
### a new data.frame has to be created
if (is.factor(subnets$country))
  subnets$country <- as.character(subnets$country)

countries <- ddply(subnets, .(country), summarize, N=sum(N))

if (is.factor(countries$country))
  countries$country <- as.character(countries$country)

countries <- countries[order(countries$country, decreasing = TRUE),]
countries$country <- factor(countries$country, levels=countries$country[order(countries$N)])

if (require(cairoDevice)) {
  Cairo_png("country.png", width=9, height=9)
} else {
  pdf("country.pdf", paper="special", width=9, height=9)
}
p <- ggplot(subset(countries, N>1), aes(x=country, y=N, fill=country))
p <- p + geom_bar(stat = "identity")
p <- p + scale_y_log10()
p <- p + guides(fill=FALSE)
p <- p + coord_flip()
print(p)
dummy <- dev.off()

############################
### since I now have the failed login attempts per country
### I can also display it in a map

### available here: http://thematicmapping.org/downloads/world_borders.php
world <- readOGR("data/GIS/", layer="TM_WORLD_BORDERS-0.3")

fworld <- fortify(world, region="ISO2")
fworld <- rename(fworld, c("id"="ISO2"))
fworld <- merge(fworld, world@data, all.x=TRUE, by="ISO2")

fworld$N <- NA
for (i in 1:nrow(countries)) {
  fworld$N[fworld$ISO2 == countries$country[i]] = log10(countries$N[i])
}

if (require(cairoDevice)) {
  Cairo_png("map.png", width=9, height=6)
} else {
  pdf("map.pdf", paper="special", width=9, height=6)
}
p <- ggplot(fworld, aes(long, lat, group = group, fill = N))
p <- p + geom_polygon()
p <- p + coord_fixed(xlim=c(-180,180), ylim=c(-90,90))
p <- p + scale_fill_gradientn("log10(N)", colours=c("#000066", "#FFFF00", "#FF0000"),
                               na.value = "grey70")
p <- p + theme(legend.position="bottom", legend.key.width=unit(0.15, "npc"))
print(p)
dummy <- dev.off()
