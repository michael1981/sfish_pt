# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-23.xml
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
 script_id(14509);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-23");
 script_cve_id("CVE-2004-0434");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-23
(Heimdal: Kerberos 4 buffer overflow in kadmin)


    A buffer overflow was discovered in kadmind, a server for administrative
    access to the Kerberos database.
  
Impact

    By sending a specially formatted message to kadmind, a remote attacker may
    be able to crash kadmind causing a denial of service, or execute arbitrary
    code with the permissions of the kadmind process.
  
Workaround

    For a temporary workaround, providing you do not require Kerberos 4
    support, you may turn off Kerberos 4 kadmin by running kadmind with the
    --no-kerberos4 option.
  
');
script_set_attribute(attribute:'solution', value: '
    All Heimdal users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-crypt/heimdal-0.6.2"
    # emerge ">=app-crypt/heimdal-0.6.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.pdc.kth.se/heimdal/advisory/2004-05-06/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0434');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-23] Heimdal: Kerberos 4 buffer overflow in kadmin');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Heimdal: Kerberos 4 buffer overflow in kadmin');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/heimdal", unaffected: make_list("ge 0.6.2"), vulnerable: make_list("lt 0.6.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
