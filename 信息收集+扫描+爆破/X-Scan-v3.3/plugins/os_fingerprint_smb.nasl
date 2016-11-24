#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25252);
  script_version("$Revision: 1.5 $");

  name["english"] = "OS Identification : SMB";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to determine the remote operating system by
connecting to remote SMB server." );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type and 
version by connecting to the remote SMB server." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
  script_summary(english:"Determines the remote operating system");
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/ProdSpec");
  exit(0);
}



if ( content = get_kb_item("SMB/ProdSpec") )
{
  product = egrep(pattern:"^Product=", string:strstr(content, "Product="));
  lang    = egrep(pattern:"^Localization=", string:strstr(content, "Localization="));
  if (strlen(product)) {
	 product -= "Product=";
         end = strstr(product, '\n');
         product = product - end;
	 lang    -= "Localization=";
	 end = strstr(lang, '\n');
	 lang = lang - end;
	 if ( "Service Pack" >!< sp ) sp = "";
         else sp = " " + sp ;
	 version = "Microsoft " + product + sp + " (" + lang + ")";
         set_kb_item(name:"Host/OS/SMB", value:version);
         set_kb_item(name:"Host/OS/SMB/Confidence", value:100);
         set_kb_item(name:"Host/OS/SMB/Type", value:"general-purpose");
         exit(0);
       }
} 
