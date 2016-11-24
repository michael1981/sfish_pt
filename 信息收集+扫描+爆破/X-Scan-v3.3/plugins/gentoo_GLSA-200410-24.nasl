# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-24.xml
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
 script_id(15560);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200410-24");
 script_cve_id("CVE-2004-0971");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-24
(MIT krb5: Insecure temporary file use in send-pr.sh)


    The send-pr.sh script creates temporary files in world-writeable
    directories with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When
    send-pr.sh is called, this would result in the file being overwritten
    with the rights of the user running the utility, which could be the
    root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MIT krb5 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-crypt/mit-krb5-1.3.4-r1"
    # emerge ">=app-crypt/mit-krb5-1.3.4-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0971');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-24] MIT krb5: Insecure temporary file use in send-pr.sh');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT krb5: Insecure temporary file use in send-pr.sh');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.3.5-r1", "rge 1.3.4-r1"), vulnerable: make_list("le 1.3.5")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
