# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-19.xml
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
 script_id(14505);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-19");
 script_cve_id("CVE-2004-0473");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-19
(Opera telnet URI handler file creation/truncation vulnerability)


    The telnet URI handler in Opera does not check for leading \'-\'
    characters in the host name. Consequently, a maliciously-crafted
    telnet:// link may be able to pass options to the telnet program
    itself. One example would be the following:
    telnet://-nMyFile
    If MyFile exists in the user\'s home directory and the user clicking on
    the link has write permissions to it, the contents of the file will be
    overwritten with the output of the telnet trace information. If MyFile
    does not exist, the file will be created in the user\'s home directory.
  
Impact

    This exploit has two possible impacts. First, it may create new files
    in the user\'s home directory. Second, and far more serious, it may
    overwrite existing files that the user has write permissions to. An
    attacker with some knowledge of a user\'s home directory might be able
    to destroy important files stored within.
  
Workaround

    Disable the telnet URI handler from within Opera.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users are encouraged to upgrade to the latest version of the
    program:
    # emerge sync
    # emerge -pv ">=www-client/opera-7.50_beta1"
    # emerge ">=www-client/opera-7.50_beta1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=104&type=vulnerabilities&flashstatus=true');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0473');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-19] Opera telnet URI handler file creation/truncation vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera telnet URI handler file creation/truncation vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 7.50_beta1"), vulnerable: make_list("lt 7.50_beta1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
