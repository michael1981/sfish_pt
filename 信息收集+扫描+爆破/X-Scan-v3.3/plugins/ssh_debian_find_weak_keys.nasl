#TRUSTED 5a84e8167858c0b50235068c27296312dd1a4c84af93d5c10bcfa6d392f051b4b3f31eeff7ebee58a482857b9d802e9533f1659b779c6c68c1ebb19d15bcff38ed799f87aeb35175037b596d4812d1e4dd616a8a56fd35cb283397a32c1fd6409cf5adb779023a156017ebfc03e8363060e2e406aa764743a6be34cf51bc6c63d5fc59d58cca5e77737fecddf7a834843a760609775057db41b86092272fa59bb8663bcdd44f84dbd644fa31268efad47605cc76d3d4e38a1344d551b0f70fc940862195f6fd1fe4bb3cdf5949ead88ae362ca8abf512567e62863c3413dcf3c7e4070361edc333733c22d046364be1e5a3d760d16aa35d56fe2377f8ad54fad7eff9077d7af8c1d014baeb810411e825b1b42416817e0c9b78ac080332731bee59f61cceb018bc1de5defb5f68bf5214a84e3affc3c378900a2518683936f664aadb3cdd027ed5fb4dc0312ce594f336b63bbc1ebe1fe0a42a1408156159b23d2c326aeabbfff34be1349a59e1e1dba1dcc3df046eae59ab9a1a444a89f2345a1c103385b1d7bba3a96e7bffc18d304ede0a00b38e55e7f536779b003945b2f1dffb29f8db410e06675017b372e158b56283e722b547c36407e37b333c87d5e6f85536396b1f1f50f6dddbd646d3bda1325b57996c8b5332014ea04728c470b882ee97f604c4aebfed5a0c6547eda5e06814527d3669264302bbfa3b23ceb80
#
# (C) Tenable Network Security, Inc.
#
if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(32320);
 script_version ("1.6");

 script_cve_id("CVE-2008-0166");
 script_bugtraq_id(29179);

 name["english"] = "Remote host has weak Debian OpenSSH Keys in ~/.ssh/authorized_keys";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH host is set up to accept authentication with
weak Debian SSH keys." );
 script_set_attribute(attribute:"description", value:
"The remote host has one or more ~/.ssh/authorized_keys
files containing weak SSH public keys generated on a Debian
or Ubuntu system.

The problem is due to a Debian packager removing nearly all
sources of entropy in the remote version of OpenSSL. 

This problem does not only affect Debian : any user uploading
a weak SSH key into his ~/.ssh/authorized_keys file will
compromise the security of the remote system.

An attacker could try a brute force attack against the remote
host and log in with these weak keys." );
 script_set_attribute(attribute:"solution", value:
"Remove all the offending entries from ~/.ssh/authorized_keys" );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
	
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH public keys");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("ssh_detect.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}
include("byte_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


SSH_RSA = 0;
SSH_DSS = 1;



function file_read_dword(fd)
{
 local_var dword;

 dword = file_read(fp:fd, length:4);
 dword = getdword(blob:dword, pos:0);

 return dword;
}


function find_hash_list(type, first, second)
{
 local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file, tmp_list;
 
 if (type == SSH_RSA)
   file = "blacklist_rsa.inc";
 else if (type == SSH_DSS)
   file = "blacklist_dss.inc";

 if ( ! file_stat(file) ) return NULL;

 fd = file_open(name:file, mode:"r");
 if (!fd) return NULL;

 main_index = file_read_dword(fd:fd);

 for (i=0; i<main_index; i++)
 {
  c = file_read(fp:fd, length:1);
  offset = file_read_dword(fd:fd);
  length = file_read_dword(fd:fd);

  if (c == first)
  {
   file_seek(fp:fd, offset:offset);
   sec_index = file_read_dword(fd:fd);

   for (j=0; j<sec_index; j++)
   {
    c = file_read(fp:fd, length:1);
    offset = file_read_dword(fd:fd);
    length = file_read_dword(fd:fd);

    if (c == second)
    {
     file_seek(fp:fd, offset:offset);
     tmp_list = file_read(fp:fd, length:length);

     len = strlen(tmp_list);
     pos = 0;

     for (j=0; j<len; j+=10)
       list[pos++] = substr(tmp_list, j, j+9);

     break;
    }
   }

   break;
  }
 }

 file_close(fd);

 return list;
}

function is_vulnerable_fingerprint(type, fp)
{
 local_var list, i, len;

 list = find_hash_list(type:type, first:fp[0], second:fp[1]);
 if (isnull(list))
   return FALSE;

 len = max_index(list);
 
 for (i=0; i<len; i++)
   if (list[i] == fp)
     return TRUE;

 return FALSE;
}

function wrapline()
{
 local_var ret;
 local_var i, l, j;
 local_var str;
 str = _FCT_ANON_ARGS[0];
 l = strlen(str);
 for ( i = 0 ; i < l; i += 72 )
 {
   for ( j = 0 ; j < 72 ; j ++ )
   {
      ret += str[i+j];
      if ( i + j + 1 >= l ) break;
   }
   ret += '\n';
 }
 return ret;
}
 

function get_key()
{
 local_var pub, public, pubtab, num, i, line,blobpub,fingerprint,ret ;
 local_var pub_array;
 local_var report;
 local_var flag;
 local_var path;
 local_var file;
 
 path = _FCT_ANON_ARGS[0];
 flag = 0;
 report = ". In file " + path + ':\n';
 file = info_send_cmd(cmd:"cat " + path);
 if ( ! file ) return NULL;
 pub_array = split(file, keep:FALSE);
 foreach pub ( pub_array ) 
 {
  line ++;
  if ( pub !~ "ssh-[rd]s[sa]" ) continue;
  public = ereg_replace(pattern:".*ssh-[rd]s[sa] ([A-Za-z0-9+/=]+) .*$",
	                  string:pub,
		          replace:"\1");
  if ( public == pub ) continue;

 blobpub = base64decode(str:public);
 fingerprint = substr(MD5(blobpub), 6, 15);
 if ("ssh-rsa" >< blobpub)
 {
 ret = is_vulnerable_fingerprint(type:SSH_RSA, fp:fingerprint);
 if (ret)
   {
    report += "line " + line + ':\n' + wrapline(pub);
    flag ++;
   }
 }
else
 { 
  ret = is_vulnerable_fingerprint(type:SSH_DSS, fp:fingerprint);
 if (ret)
  {
    report += "line " + line + ':\n' + wrapline(pub);
    flag ++;
  }
 }
 }
 
 if ( flag == 0 ) return NULL;
 return report;
}


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

cmd = info_send_cmd(cmd:"cat /etc/passwd");
if ( ! cmd ) exit(0);
homes = make_list();
foreach line ( split(cmd) )
{
 entries = split(line, sep:':', keep:FALSE);
 if ( max_index(entries) > 5 ) 
  {
    homes[entries[5]] = TRUE;   
  }
}

homes = keys(homes);
foreach home ( homes )
{
 report += get_key(home + "/.ssh/authorized_keys");
 report += get_key(home + "/.ssh/id_dsa.pub");
 report += get_key(home + "/.ssh/id_rsa.pub");
}

if ( report )
{
 security_hole(port:kb_ssh_transport(), extra:report);
}
