#TRUSTED 3372dd4d9193da6d178da1d5a153c77f93155def3ea9a41f14db7813d6e6a4694dae537a63333d953d27e9e75236aa7ae157ad2378d927a2090611864013a91c2981b572deee16d20166f21b69d6bd1f7470c44bf0e0ee45ed09c940276490b81f061a8de4c4d16768982c6aa5ef6a4b5b6925688aa4cac3a7d04f67ef82e615e38b25fdd561fd8dfe61cfeceba5ad6bfbeccdf99994f43a083421738e8da9fbf20aac944420937d564863124c1a641164124a2960ac25505b9c0c6d1efa8bec382d88fb29b2128ca16ab7dc3be5890fd0e8307182e2c17dd5dd6f0c1772d6de7bd571c1ce82d7117878e90fa1c2eadebd850a02359c097c7259eb85e75375138c2011be59220541a85eb3670d0a037a37e01f21a30c5112622fbcf213fe3ecca2f9f0211f39ddf90b4fa9931bdaac51a4301791fa3cb8862a766dbe01a6b7c4e315d48ce3d8e7e01c8791451ddb1ec43014a70ca7cf9d7b8a8191f2ec2585e028eb07f8f6f31d7bad887ecdd2dd08218adb76542d8339e3a9498af2e3d9d545fed1aee8f1ada0728715c9942874627573466ca49d4594ebfbb51685e2715dae55fd07eb5442a94ebf498d8ff7042338141f834c5f928cd93130c04d674e67a32d4c7836d95d9a59edd0ba332c4a601a62f7ffb9e9963e94b6f7e19e587753eb17c7dc28b52db29eee7130b6d763a525034fcf7944c4c324e31fc4b3f5c9eabd
#
# This script was written by Tenable Network Security
#
if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(34030);
 script_version ("1.2");

 script_cve_id("CVE-2008-3844");
 script_bugtraq_id(30794);
 script_xref(name:"OSVDB", value:"47635");

 name["english"] = "Remote host has a compromised Red Hat OpenSSH package intalled";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a compromised version of an OpenSSH-related
package installed." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a compromised version of an OpenSSH-related
package installed. 

Even though this package has been signed with the Red Hat public key,
this package is considered malicious, and the remote host should be
reinstalled." );
 script_set_attribute(attribute:"see_also", value:"http://www.redhat.com/security/data/openssh-blacklist.html" );
 script_set_attribute(attribute:"solution", value:
"Reintall the remote host." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security, Inc");
 script_family(english:"Red Hat Local Security Checks");

 script_dependencie("ssh_detect.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


list = make_list(
"Host/VMware/rpm-list",
"Host/RedHat/rpm-list",
"Host/CentOS/rpm-list",
"Host/Mandrake/rpm-list",
"Host/SuSE/rpm-list");

flag = 0;

foreach item ( list ) 
{
 if ( get_kb_item(item) ) flag ++;
} 

if ( ! flag ) exit(0);



if ( islocalhost() )
{
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if ( !sock_g ) exit(0);
 info_t = INFO_SSH;
}

md5 = make_list(
"00b6c24146eb6222ec58342841ee31b1",
"021d1401b2882d864037da406e7b3bd1",
"035253874639a1ebf3291189f027a561",
"08daefebf2a511852c88ed788717a148",
"177b1013dc0692c16e69c5c779b74fcf",
"24c67508c480e25b2d8b02c75818efad",
"27ed27c7eac779f43e7d69378a20034f",
"2a2f907c8d6961cc8bfbc146970c37e2",
"2b0a85e1211ba739904654a7c64a4c90",
"2df270976cbbbbb05dbdf95473914241",
"2ff426e48190519b1710ed23a379bbee",
"322cddd04ee5b7b8833615d3fbbcf553",
"35b050b131dab0853f11111b5afca8b3",
"38f67a6ce63853ad337614dbd760b0db",
"3b9e24c54dddfd1f54e33c6cdc90f45c",
"3fa1a1b446feb337fd7f4a7938a6385f",
"41741fe3c73d919c3758bf78efc437c9",
"432b94026da05d6b11604a00856a17b2",
"54bd06ebf5125debe0932b2f1f5f1c39",
"57f7e73ee28ba0cbbaad1a0a63388e4c",
"59ad9703362991d8eff9d138351b37ac",
"71ef43e0d9bfdfada39b4cb778b69959",
"760040ec4db1d16e878016489703ec6d",
"89892d38e3ccf667e7de545ea04fa05b",
"8a65c4e7b8cd7e11b9f05264ed4c377b",
"8bf3baa4ffec125206c3ff308027a0c4",
"982cd133ba95f2db580c67b3ff27cfde",
"990d27b6140d960ad1efd1edd5ec6898",
"9bef2d9c4c581996129bd9d4b82faafa",
"9c90432084937eac6da3d5266d284207",
"a1dea643f8b0bda52e3b6cad3f7c5eb6",
"b54197ff333a2c21d0ca3a5713300071",
"b92ccd4cbd68b3d3cefccee3ed9b612c",
"bb1905f7994937825cb9693ec175d4d5",
"bc6b8b246be3f3f0a25dd8333ad3456b",
"c0aff0b45ee7103de53348fcbedaf72e",
"c7d520faab2673b66a13e58e0346021d",
"ce97e8c02c146c8b1075aad1550b1554",
"d19ae2199662e90ec897c8f753816ee0",
"de61e6e1afd2ca32679ff78a2c3a0767",
"dfbc24a871599af214cd7ef72e3ef867",
"f68d010c6e54f3f8a973583339588262",
"fc814c0e28b674da8afcfbdeecd1e18e"
);

res = info_send_cmd(cmd:'rpm -q --qf "%{NAME}/%{SIGMD5}\\n" openssh openssh-askpass openssh-askpass-gnome openssh-clients openssh-debuginfo openssh-server');

if ( ! res ) exit(0);
report = NULL;
foreach md (md5) 
{
 if ( md >< res )
 {
   line = chomp(egrep(pattern:md, string:res));
   split = split(line, sep:'/',keep:0);
   report += 'Package name : ' + split[0]  + '\nPackage MD5 : ' + split[1] + '\n\n';
 }
}

if ( report )
{
 security_hole(port:0, extra:'\nThe following packages are vulnerables :\n' + report);
}
