# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-30.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(17233);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200502-30");
 script_cve_id("CVE-2005-0580");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-30 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-30
(cmd5checkpw: Local password leak vulnerability)


    Florian Westphal discovered that cmd5checkpw is installed setuid
    cmd5checkpw but does not drop privileges before calling execvp(), so
    the invoked program retains the cmd5checkpw euid.
  
Impact

    Local users that know at least one valid /etc/poppasswd user/password
    combination can read the /etc/poppasswd file.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All cmd5checkpw users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/cmd5checkpw-0.22-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0580');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-30.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-30] cmd5checkpw: Local password leak vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cmd5checkpw: Local password leak vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/cmd5checkpw", unaffected: make_list("ge 0.22-r2"), vulnerable: make_list("le 0.22-r1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
