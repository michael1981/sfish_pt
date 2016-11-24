# -*- Fundamental -*-
# backport.inc
#
# $Id: backport.inc,v 1.61 2009/10/20 22:28:25 theall Exp $
# 
# (C) Tenable Network Security, Inc.
#
#
# When a security flaw is discovered, many OS vendors do not update the product
# to its latest version, but tend to backport the patches instead. This module
# does a translation between the "fixed" (according to the vendor) products, and
# the latest version number.
#
# Credits: This excellent idea comes is from Laurent FACQ (facq@u-bordeaux.fr) 
# and was initially designed to handle Debian. The idea has then been 
# extended to a broader scope than Debian only.
#
# Usage : 
#  new_banner = get_backport_banner(banner:orig_banner);
#
#
#

global_var backported;

backported = 0;

function get_backport_banner(banner)
{
 local_var i, j,k,l,backported_versions, real_versions, rx_backported_versions, rx_real_versions, paranoia, str;

 backported = 0;
 paranoia = get_kb_item("global_settings/report_paranoia");
 if ( "Paranoid" >< paranoia ) return banner;

 

 i = 0;
 j = 0;
 k = 0;
 l = 0;

#
# Debian
#   
# Security support for old versions is over

rx_backported_versions[k++] = '.*OpenSSH_3\\.4p1 Debian 1:3.4p1-1\\.woody\\.3';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedDebian 1:3.4p1-1.woody.3";


rx_backported_versions[k++] = '.*OpenSSH_4\\.3p2 Debian';
rx_real_versions[l++] = 'SSH-2.0-OpenSSH_9.99p9 ConvertedDebian';


rx_backported_versions[k++] = '.*OpenSSH_3\\.6\\.1p2 Debian 1:3\\.6\\.1p2-3\\.sarge\\.1';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedDebian 1:3.6.1p2-3.sarge.1";

backported_versions[i++] = 'OpenSSH_3.8.1p1 Debian-8.sarge.4';
real_versions[j++]        = 'OpenSSH_9.9.99p1 ConvertedDebian';

backported_versions[i++] = 'OpenSSH_4.3p2 Debian-9etch';
real_versions[j++]        = 'OpenSSH_9.9.99p1 ConvertedDebian';

backported_versions[i++] = "Sendmail 8.12.3/8.12.3/Debian-6.6;";
real_versions[j++]	 = "Sendmail 8.12.10/8.12.10/ConvertedDebian;";

backported_versions[i++] = "SSH-2.0-dropbear_0.45";	# Sarge
real_versions[j++]	 = "SSH-2.0-dropbear_0.99";

#
# MacOS X
# 

rx_backported_versions[k++] = 'OpenSSH_3\\.6\\.1p1\\+CAN-2003-0693';
rx_real_versions[l++]	 = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedMacOSX+CAN-2003-0693";

rx_backported_versions[k++] = 'OpenSSH_3\\.6\\.1p1\\+CAN-2004-0175';
rx_real_versions[l++]	 = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedMacOSX+CAN-2004-0175";
#
# AltLinux 
#
rx_backported_versions[k++] = 'OpenSSH_3\\.6\\.1p2-alt4';
rx_real_versions[l++]       = "SSH-2.0-OpenSSH_9.9.99-convertedAlt4";


# 
# FreeBSD
#
rx_backported_versions[k++] = "OpenSSH.*FreeBSD.*(20030916|200[4-9])";
rx_real_versions[l++]       = "OpenSSH_3.7.1p2 ConvertedFreeBSD-20030916";


#
# IBM's Apache
# 
backported_versions[i++]   = "IBM_HTTP_SERVER/1.3.19.4 Apache/1.3.20"; 
real_versions[j++]         = "Apache/1.3.28 (ConvertedIBM)";

rx_backported_versions[k++] = "IBM_HTTP_SERVER/2\.0\.47\.[1-9]\.";
rx_real_versions[l++]	   = "Apache/2.0.49 (ConvertedIBM)";

rx_backported_versions[k++]   = "IBM_HTTP_Server/6\.0\.[0-9] Apache/2.0.47";
rx_real_versions[l++]         = "Apache/2.0.99 (ConvertedIBM)";

rx_backported_versions[k++]   = "IBM_HTTP_Server/6\.0\.2\.[0-9]+ Apache/2.0.47";
rx_real_versions[l++]         = "Apache/2.0.99 (ConvertedIBM)";

rx_backported_versions[k++]   = "IBM_HTTP_Server/6\.1\.0\.[0-9]+ Apache/2.0.47";
rx_real_versions[l++]         = "Apache/2.0.99 (ConvertedIBM)";

backported_versions[i++]   = "IBM_HTTP_SERVER/1.3.19.6 Apache/1.3.20"; 
real_versions[j++]         = "Apache/1.3.29 (ConvertedIBM)";


# woody
backported_versions[i++]   = "Apache/1.3.26 (Unix) Debian GNU/Linux"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedDebian)";

# etch
backported_versions[i++]   = "Apache/2.2.3 (Debian)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedDebian)";

# lenny
backported_versions[i++]   = "Apache/2.2.9 (Debian)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedDebian)";

backported_versions[i++] = "Apache/1.3.34 (Debian)";
real_versions[j++]       = "Apache/1.3.99 (ConvertedDebian)";

# Ubuntu 4.10
backported_versions[i++]   = "Apache/2.0.50 (Ubuntu)";
real_versions[j++]         = "Apache/2.0.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_3\\.8\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 5.04
backported_versions[i++]   = "Apache/2.0.53 (Ubuntu)";
real_versions[j++]         = "Apache/2.0.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_3\\.9p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 5.10
backported_versions[i++]   = "Apache/2.0.54 (Ubuntu)";
real_versions[j++]         = "Apache/2.0.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_4\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 6.06 and 6.10
backported_versions[i++]   = "Apache/2.0.55 (Ubuntu)";
real_versions[j++]         = "Apache/2.0.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_4\\.2p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

rx_backported_versions[k++] = '.*OpenSSH_4\\.3p2 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 7.04
backported_versions[i++]   = "Apache/2.2.3 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

#rx_backported_versions[k++] = '.*OpenSSH_4\\.3p2 Debian.*ubuntu';
#rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 7.10
backported_versions[i++]   = "Apache/2.2.4 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_4\\.6p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 8.04
backported_versions[i++]   = "Apache/2.2.8 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_4\\.7p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 8.10
backported_versions[i++]   = "Apache/2.2.9 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_5\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# Ubuntu 9.04
backported_versions[i++]   = "Apache/2.2.11 (Ubuntu)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedUbuntu)";

rx_backported_versions[k++] = '.*OpenSSH_5\\.1p1 Debian.*ubuntu';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_9.9.99 ConvertedUbuntu";

# ZyXEL
backported_versions[i++]   = "SSH-1.5-1.0.0"; 
real_versions[j++]         = "SSH-1.5-9.9.9";

# 
# Red Hat and others backports fixes - we can't always rely on the version 
# number
#

# Red Hat 8.0 and 9.0
backported_versions[i++]   = "Apache/2.0.40 (Red Hat Linux)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedRedHat)";

# ES2.1
backported_versions[i++]   = "Apache/1.3.27 (Unix)  (Red-Hat/Linux)"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedRedHat)";

backported_versions[i++]   = "OpenSSH_3.1p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# ES3
backported_versions[i++]   = "Apache/2.0.46 (Red Hat)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedRedHat)";

backported_versions[i++]   = "Apache/2.0.46 (CentOS)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedCentOS)";


backported_versions[i++]   = "OpenSSH_3.6.1p2"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# ES4
backported_versions[i++]   = "Apache/2.0.52 (Red Hat)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedRedHat)";

backported_versions[i++]   = "Apache/2.0.52 (CentOS)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedCentOS)";

backported_versions[i++]   = "OpenSSH_3.9p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# ES5
backported_versions[i++]   = "Apache/2.2.3 (Red Hat)"; 
real_versions[j++]         = "Apache/2.2.99 (ConvertedRedHat)";

backported_versions[i++]   = "Apache/2.2.3 (CentOS)"; 
real_versions[j++]         = "Apache/2.2.99 (ConvertedCentOS)";

backported_versions[i++]   = "OpenSSH_4.3"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# Oracle
backported_versions[i++]   = "Oracle HTTP Server Powered by Apache/1.3.19";
real_versions[j++]         = "Oracle HTTP Server Powered by Apache/1.3.99 (Converted)";

# Oracle again
backported_versions[i++]   = "Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_perl/1.22";
real_versions[j++]         = "Apache/1.3.99 (Win32) ApacheJServ/9.9 mod_perl/9.99";



# CPanel
rx_backported_versions[k++] = "Apache/1\.3\.37 \(Unix\).*mod_auth_passthrough/1\.8.*mod_bwlimited/1\.4.*mod_ssl/2\.8\.28";
rx_real_versions[l++]        = "Apache/1.9.99";


backported_versions[i++]   = "OpenSSH_3.9p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";


# SuSE 8.0, Red Hat 8.0
backported_versions[i++]   = "OpenSSH_3.4p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# SuSE 8.x, Red Hat 9.0
backported_versions[i++]   = "OpenSSH_3.5p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";


# SuSE 9.0
backported_versions[i++]   = "Apache/2.0.48 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_3.7.1p2"; 
real_versions[j++]         = "OpenSSH_9.9.99";

backported_versions[i++]   = "Apache/1.3.28 (Linux/SUSE)";
real_versions[j++]         = "Apache/1.3.99 (ConvertedSuSE)";

# SuSE 9.1
backported_versions[i++]   = "Apache/2.0.49 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_3.8p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# SuSE 9.2
backported_versions[i++]   = "Apache/2.0.50 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

# SSH -> Same as ES4

# SuSE 9.3
backported_versions[i++]   = "Apache/2.0.53 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

# SLES 9 SP4

backported_versions[i++]   = "OpenSSH_4.1";
real_versions[j++]         = "OpenSSH_9.9.99";

# SSH -> Same as ES4

# SuSE 10.0
backported_versions[i++]   = "Apache/2.0.54 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.1p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# SuSE 10.1
backported_versions[i++]   = "Apache/2.2.0 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.2p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# SuSE 10.2
backported_versions[i++]   = "Apache/2.2.3 (Linux/SuSE)";	# also SLES10
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.4p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# SLES 10 SP2

backported_versions[i++]   = "OpenSSH_4.2";
real_versions[j++]         = "OpenSSH_9.9.99";

# SuSE 10.3
backported_versions[i++]   = "Apache/2.2.4 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.6p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# SuSE 11
backported_versions[i++]   = "Apache/2.2.8 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "SSH-2.0-OpenSSH_5.0";
real_versions[j++]         = "OpenSSH_9.9.99";

# openSuSE 11.1
backported_versions[i++]   = "Apache/2.2.10 (Linux/SUSE)";
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "SSH-2.0-OpenSSH_5.1";
real_versions[j++]         = "OpenSSH_9.9.99";

# http://www.novell.com/products/linuxpackages/enterpriseserver/SP4/i386/index_all.html
# SuSE SLES9 SP4
backported_versions[i++]   = "Apache/1.3.29 (Linux/SUSE)"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedSuSE)";

backported_versions[i++]   = "Apache/2.0.59 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

# Mac OS X 10.4 Server
backported_versions[i++]   = "Apache/1.3.33 (Darwin)"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedDarwin)";

# Mac OS X 10.5 (Darwin becomes Unix) [2008-002 does *not* backport the fixes]
#backported_versions[i++]   = "Apache/2.2.6 (Unix) mod_ssl/2.2.6 OpenSSL/0.9.7l";
#real_versions[j++]         = "Apache/2.2.99";

# Mac OS X 10.5.2, with security update 2008-002
backported_versions[i++]   = "Apache/2.2.8 (Unix) mod_ssl/2.2.8 OpenSSL/0.9.7l";
real_versions[j++]         = "Apache/2.2.99";

# Apache Server on Mac OS X 10.6 (Client)

backported_versions[i++]   = "Apache/2.2.11 (Unix) mod_ssl/2.2.11 OpenSSL/0.9.8k DAV/2";
real_versions[j++]         = "Apache/2.2.99";

# Mac OS X Server - Admin
backported_versions[i++]   = "Apache/1.3.27 (Darwin) mod_ssl/2.8.12 OpenSSL/0.9.7b"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedDarwin) mod_ssl/2.9.99 OpenSSL/0.9.99z";

# Mac OS X Server
backported_versions[i++]   = "Apache/1.3.27 (Darwin)"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedDarwin)";


# Fedora FC1
backported_versions[i++]   = "Apache/2.0.50 (Fedora)"; 
real_versions[j++]         = "Apache/2.0.99 (Fedora)";

# Fedora FC2
backported_versions[i++]   = "Apache/2.0.51 (Fedora)"; 
real_versions[j++]         = "Apache/2.0.99 (Fedora)";

# Fedora FC3
backported_versions[i++]   = "Apache/2.0.52 (Fedora)"; 
real_versions[j++]         = "Apache/2.0.99 (Fedora)";

# Fedora FC4
backported_versions[i++]   = "Apache/2.0.54 (Fedora)"; 
real_versions[j++]         = "Apache/2.0.99 (Fedora)";

# Fedora FC5
backported_versions[i++]   = "Apache/2.2.0 (Fedora)"; 
real_versions[j++]         = "Apache/2.2.99 (Fedora)";

# Fedora FC6
backported_versions[i++]   = "Apache/2.2.3 (Fedora)"; 
real_versions[j++]         = "Apache/2.2.99 (Fedora)";

backported_versions[i++]   = "OpenSSH_4.3p2"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# Fedora FC7
backported_versions[i++]   = "Apache/2.2.4 (Fedora)"; 
real_versions[j++]         = "Apache/2.2.99 (Fedora)";

backported_versions[i++]   = "Apache/2.2.8 (Fedora)"; 
real_versions[j++]         = "Apache/2.2.99 (Fedora)";

backported_versions[i++]   = "OpenSSH_4.5p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# Fedora FC8
backported_versions[i++]   = "Apache/2.2.6 (Fedora)"; 
real_versions[j++]         = "Apache/2.2.99 (Fedora)";

backported_versions[i++]   = "OpenSSH_4.7p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# Fedora FC9
backported_versions[i++]   = "Apache/2.2.9 (Fedora)"; 
real_versions[j++]         = "Apache/2.2.99 (Fedora)";

backported_versions[i++]   = "OpenSSH_5.0p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# Fedora FC10
backported_versions[i++]   = "Apache/2.2.11 (Fedora)"; 
real_versions[j++]         = "Apache/2.2.99 (Fedora)";

backported_versions[i++]   = "OpenSSH_5.1p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# Fedora FC11
backported_versions[i++]   = "Apache/2.2.11 (Fedora)"; 
real_versions[j++]         = "Apache/2.2.99 (Fedora)";

backported_versions[i++]   = "OpenSSH_5.2p1"; 
real_versions[j++]         = "OpenSSH_9.9.99";

# Debian - wu-ftpd
backported_versions[i++]   = "FTP Server (Version wu-2.6.2";
real_versions[j++]         = "FTP Server (Version wu-2.9.99";

if ( "Avoid false alarms" ><  paranoia && "Normal" >!< paranoia )
{
 # OpenBSD 
 backported_versions[i++]   = "Server: Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7j";
 real_versions[j++]         = "Server: Apache/1.3.99 (OpenBSD) mod_ssl/2.9.99 OpenSSL/0.9.99z";
}

for ( i = 0 ; backported_versions[i] ; i ++ )
 { 
 if ( tolower(backported_versions[i]) >< tolower(banner) ) 
	{
	 str = ereg_replace(pattern:"([\\?.*(){}^$])", replace:"\\1", string:backported_versions[i]);
	 backported = 1;
	 if ( defined_func("replace_kb_item") ) replace_kb_item(name:"general/backported", value:TRUE);
	 return ereg_replace(pattern:str, replace:real_versions[i], string:banner, icase:TRUE);
	}
 }

 for ( i = 0; rx_backported_versions[i]; i ++ )
 {
  if ( egrep(pattern:rx_backported_versions[i], string:banner, icase:TRUE) ) 
   {
   backported = 1;
   if ( defined_func("replace_kb_item") ) replace_kb_item(name:"general/backported", value:TRUE);
   return ereg_replace(pattern:rx_backported_versions[i], replace:rx_real_versions[i], string:banner, icase:TRUE);
   }
 }


 return banner;
}




function get_php_version(banner)
{
 local_var www_version, php_version, paranoia;
 local_var xpowered_by;
 paranoia = get_kb_item("global_settings/report_paranoia");

 www_version = banner;
 if ( ! www_version ) return NULL;

 php_version = egrep(pattern:"Server:.*PHP/[0-9].", string:www_version);
 if ( ! php_version ) {
	php_version = egrep(pattern:"^X-Powered-By:.*PHP/[0-9]", string:www_version);
	xpowered_by = 1;
	}
 if ( ! php_version ) return NULL;

 # backported by Debian
 if ("Paranoid" >!< paranoia && ereg(string: php_version, pattern: "PHP/[0-9.-]++(woody|sarge|etch|lenny)[0-9]"))
  return NULL;

 php_version = ereg_replace(pattern:".*(PHP/[0-9.]*)[^0-9.].*", string:php_version, replace:"\1");
 if ( "Paranoid" >< paranoia ) return php_version;


 # 
 # Is this a backported banner?
 #
 get_backport_banner(banner:banner);
 if ( backported ) return NULL;
 # Avoid a FP if Apache is configured as 'ProductOnly'
 if ( xpowered_by && egrep(pattern:"^Server: Apache.?$", string:www_version) )
	return NULL;

 return php_version;
}


