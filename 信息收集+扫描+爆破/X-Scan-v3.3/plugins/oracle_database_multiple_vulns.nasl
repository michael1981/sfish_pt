#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
	script_id(16209);
 	script_version ("$Revision: 1.8 $");

	script_cve_id("CVE-2004-0637", "CVE-2004-0638", "CVE-2004-1362", "CVE-2004-1363",
		      "CVE-2004-1364", "CVE-2004-1365", "CVE-2004-1366", "CVE-2004-1367",
		      "CVE-2004-1368", "CVE-2004-1369", "CVE-2004-1370", "CVE-2004-1371");
	script_bugtraq_id(12301, 10871, 11120, 11099, 11100, 11091, 12296);
	script_xref(name:"IAVA", value:"2005-A-0004");

	script_name(english:"Oracle Database Multiple Vulnerabilities (CPU Jan 2005)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Oracle Database, according to its version number,
is vulnerable to several flaws, ranging from information 
disclosure about the remote host to code execution." );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/pdf/cpu-jan-2005_advisory.pdf" );
 script_set_attribute(attribute:"solution", value:
"Oracle posted a critical patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


	script_summary(english: "Checks the version of the remote Database");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Databases");
	script_copyright(english: "This script is (C) 2005-2009 Tenable Network Security, Inc.");
	script_dependencie("oracle_tnslsnr_version.nasl");
        script_require_ports("Services/oracle_tnslsnr");
	exit(0);
}

include('global_settings.inc');

if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/oracle_tnslsnr");
if ( isnull(port)) exit(0);

version = get_kb_item(string("oracle_tnslsnr/",port,"/version"));
if (version)
{
   iversion = split(version, sep:'.', keep:FALSE);

   if ( int(iversion[0]) == 8 )
   {
     if (int(iversion[1]) == 0 ) # 8.0.6.3
     {
	 if ( int(iversion[2]) < 6 || ( int(iversion[2]) == 6 && int(iversion[3]) <= 3) )
		security_hole ( 0 );
     }
     else if ( int(iversion[1]) == 1 ) # 8.1.7.4
     {
         if ( int(iversion[2]) < 7 || ( int(iversion[2]) == 7 && int(iversion[3]) <= 4 ) )
		security_hole ( 0 );
     }
   }
   else if ( int(iversion[0]) == 9 )
   {
     if ( int(iversion[1]) == 0 )		# 9.0.1.5
	{
	 if ( int(iversion[2]) < 1 || ( int(iversion[1]) == 1 && int(iversion[2]) <=5 ) )
		security_hole ( 0 );
	}
     else if (int(iversion[1]) == 2 )      # 9.2.0.6 
	{
	 if ( int(iversion[2]) == 0 && int(iversion[3]) <= 6 )
		security_hole ( 0 );
	}
    } 
    else if ( int(iversion[0]) == 10 )
    {
	 # 10.1.0.3.1
	 if ( int(iversion[1]) == 1 )
	 {
           if ( int(iversion[2]) == 0 && int(iversion[3]) < 3 )
		security_hole( 0 );
	   if ( !isnull(iversion[4]) )
	   {
             if ( int(iversion[2]) == 0 && int(iversion[3]) == 3  && int(iversion[4]) <= 1 )
		security_hole( 0 );
	   }
	  else if ( int(iversion[2]) == 0 && int(iversion[3]) == 3 )	
		security_hole ( 0 );
         }
    }
}
