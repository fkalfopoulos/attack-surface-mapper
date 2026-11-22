namespace AttackSurfaceMapper.Domain;

/// <summary>
/// Τα κείμενα των προβλημάτων DNS/email. Είναι κοινά ανάμεσα στο module που τα εντοπίζει και
/// στους κανόνες συσχέτισης που τα συνδυάζουν, ώστε να μη "σπάσει" ο κανόνας αν αλλάξει το κείμενο.
/// </summary>
public static class DnsIssues
{
    /// <summary>Το domain δεν έχει SPF record.</summary>
    public const string NoSpf = "Δεν υπάρχει SPF: οποιοσδήποτε μπορεί να στείλει email ως το domain";

    /// <summary>Το domain δεν έχει DMARC record.</summary>
    public const string NoDmarc = "Δεν υπάρχει DMARC: τα πλαστά emails δεν απορρίπτονται";

    /// <summary>Το SPF επιτρέπει σε όλους να στέλνουν email.</summary>
    public const string SpfAllowsAll = "Το SPF επιτρέπει σε ΟΛΟΥΣ να στέλνουν email (+all)";

    /// <summary>Υπάρχουν πολλαπλά SPF records (άκυρο κατά το RFC 7208).</summary>
    public const string MultipleSpf = "Πολλαπλά SPF records: σύμφωνα με το RFC 7208 το SPF θεωρείται άκυρο";

    /// <summary>Αρχή του μηνύματος όταν ένας nameserver επιτρέπει zone transfer (ακολουθεί το όνομά του).</summary>
    public const string ZoneTransfer = "Επιτρέπεται zone transfer (AXFR) από";

    /// <summary>Το DMARC μόνο παρακολουθεί (p=none).</summary>
    public const string DmarcNone = "DMARC με p=none: μόνο παρακολούθηση, τα πλαστά emails παραδίδονται";
}
