#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(27525);
 script_version ("$Revision: 1.12 $");

 name["english"] = "Microsoft Office service pack not up to date";

 script_name(english:name["english"]);

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote office suite is not up to date."
  )
 );
 script_set_attribute(
   attribute:"description",
   value:string(
    "The remote version of Microsoft Office has no service pack or the one\n",
    "installed is no longer supported."
   )
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://support.microsoft.com/gp/lifesupsps#Office"
 );
 script_set_attribute(
  attribute:"solution",
  value:"Install the latest service pack."
 );
 script_set_attribute(
  attribute:"cvss_vector",
  value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 summary["english"] = "Determines the remote Office SP";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("office_installed.nasl");
 script_require_keys("SMB/Office/Version");
 exit(0);
}


office_sp["2000"] = 3;
office_sp["XP"] = 3;
office_sp["2003"] = 3;
office_sp["2007"] = 2;

office_min_sp["2000"] = 3;
office_min_sp["XP"] = 3;
office_min_sp["2003"] = 3;
office_min_sp["2007"] = 1;

report = NULL;

l = get_kb_list("SMB/Office/Version");
if (isnull(l)) exit(1, "The 'SMB/Office/Version' KB item is missing.");
version_list = make_list(l);

l = get_kb_list("SMB/Office/SP");
if (isnull(l)) exit(1, "The 'SMB/Office/SP' KB item is missing.");
sp_list = make_list(l);

if ( max_index( version_list ) != max_index( sp_list ) )
 exit( 1, 'The list of installed Office version is not balanced with the list of installed Office Service Packs.' );

for ( i = 0; i < max_index( version_list ); i++ )
{
 version = version_list[ i ];
 sp = sp_list[ i ];

 if (sp == 0)
   report_detail = "no service pack";
 else
   report_detail = string("Service Pack ", sp);

 if (sp < office_min_sp[version])
 {
  report += string ("\n",
   "The remote Microsoft Office ", version, " system has ", report_detail , " applied.\n",
   "The system should have Office ", version, " Service Pack ", office_sp[version], " installed.\n");
 }
}

if ( report )
 security_hole(extra:report, port:get_kb_item("SMB/transport"));
