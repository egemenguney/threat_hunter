/*
    Delta Force Malware YARA Rules
    
    These rules detect malware repositories and payloads associated with
    the "Delta Force hack" malware distribution campaign on GitHub.
    
    Author: Security Research
    Date: December 2025
    Version: 1.1 - Enhanced with scan results patterns
*/

// ============================================================================
// CYRILLIC OBFUSCATION DETECTION
// ============================================================================

rule Cyrillic_Loader_Filename
{
    meta:
        description = "Detects Cyrillic 'о' (U+043E) obfuscation in Loader filenames"
        author = "Security Research"
        severity = "HIGH"
        category = "obfuscation"
        
    strings:
        // Cyrillic 'о' = D0 BE in UTF-8
        $loader_cyrillic = { 4C D0 BE 61 64 65 72 }  // "Lоader" with Cyrillic о
        $loader_zip = "L\xd0\xbeader.zip"
        $loader_rar = "L\xd0\xbeader.rar"
        
    condition:
        any of them
}

rule Cyrillic_Homoglyph_General
{
    meta:
        description = "Detects various Cyrillic homoglyph obfuscation"
        author = "Security Research"
        severity = "MEDIUM"
        
    strings:
        // Common Cyrillic/Latin confusables in filenames
        $cyr_a = { D0 B0 }  // Cyrillic а
        $cyr_e = { D0 B5 }  // Cyrillic е
        $cyr_o = { D0 BE }  // Cyrillic о
        $cyr_p = { D1 80 }  // Cyrillic р
        $cyr_c = { D1 81 }  // Cyrillic с
        $cyr_x = { D1 85 }  // Cyrillic х
        
        // Common malware filenames that might use these
        $setup = "Setup" nocase
        $install = "Install" nocase
        $loader = "Loader" nocase
        $hack = "Hack" nocase
        
    condition:
        any of ($cyr_*) and any of ($setup, $install, $loader, $hack)
}

// ============================================================================
// README SOCIAL ENGINEERING PATTERNS
// ============================================================================

rule Readme_Disable_Antivirus
{
    meta:
        description = "README instructs user to disable antivirus"
        author = "Security Research"
        severity = "HIGH"
        category = "social_engineering"
        
    strings:
        $disable1 = "disable antivirus" nocase
        $disable2 = "disable defender" nocase
        $disable3 = "turn off antivirus" nocase
        $disable4 = "disable your antivirus" nocase
        $disable5 = "antivirus interference" nocase
        $disable6 = "disable av" nocase
        $disable7 = "turn off your antivirus" nocase
        
        // New patterns from scan results
        $undetected = "undetected" nocase
        $antiban1 = "anti-ban" nocase
        $antiban2 = "anti ban" nocase
        $bypass1 = "bypass detection" nocase
        $bypass2 = "stealth mode" nocase
        
    condition:
        any of them
}

rule Readme_Fake_Verification
{
    meta:
        description = "Fake GitHub/VirusTotal verification claims"
        author = "Security Research"
        severity = "HIGH"
        category = "social_engineering"
        
    strings:
        $fake1 = "GITHUB VERIFIED" nocase
        $fake2 = "GITHUB VERIFED" nocase  // Common typo
        $fake3 = "VirusTotal Certified" nocase
        $fake4 = "Verified Publisher" nocase
        $fake5 = "✓ Verified" nocase
        $fake6 = "✅ Verified" nocase
        
    condition:
        any of them
}

rule Readme_Password_Hint
{
    meta:
        description = "Password hints for protected archives"
        author = "Security Research"
        severity = "MEDIUM"
        category = "social_engineering"
        
    strings:
        $pass1 = /PASS\s*[-:=]\s*\d{3,}/
        $pass2 = /password\s*[-:=]\s*\d{3,}/i
        $pass3 = "password: 1212"
        $pass4 = "pass: 1212"
        $pass5 = /archive password/i
        
    condition:
        any of them
}

rule Readme_Bot_Generated
{
    meta:
        description = "Bot-generated README patterns"
        author = "Security Research"
        severity = "MEDIUM"
        category = "bot_content"
        
    strings:
        $bot1 = "Windows 2025"  // Non-existent OS
        $bot2 = "2025 Edition"
        $bot3 = "SEO Keywords:" nocase
        $bot4 = "SEO-Friendly Keywords" nocase
        $bot5 = /MIT License.*hack/is
        $bot6 = "educational purposes only" nocase
        $bot7 = "strictly for educational" nocase
        
        // New patterns from scan results
        $bot8 = /\d{4}.*Edition/  // Dynamic year editions
        $bot9 = /Windows\s*\d{4}/  // Future Windows versions
        $bot10 = /latest.*\d{4}.*version/i
        $bot11 = /updated.*\d{4}/i
        $bot12 = /\d{4}.*hack.*tool/i
        $bot13 = /\d{4}.*cracked/i
        
        // Excessive emoji patterns - using hex bytes for emojis
        // Rocket emoji: F0 9F 9A 80, Fire: F0 9F 94 A5
        $emoji_rocket = { F0 9F 9A 80 }
        $emoji_fire = { F0 9F 94 A5 }
        
    condition:
        2 of ($bot*) or ($emoji_rocket and $emoji_fire)
}

// ============================================================================
// KNOWN MALICIOUS INFRASTRUCTURE
// ============================================================================

rule Known_C2_Domains
{
    meta:
        description = "Known malicious C2 domains from this campaign"
        author = "Security Research"
        severity = "CRITICAL"
        category = "infrastructure"
        
    strings:
        $c2_1 = "kiamatka.com"
        $c2_2 = "hanblga.com"
        $c2_3 = "cheatseller.ru"
        $c2_4 = "get-hacks.xyz"
        
    condition:
        any of them
}

rule Known_Mediafire_Payloads
{
    meta:
        description = "Known malicious MediaFire folder IDs"
        author = "Security Research"
        severity = "HIGH"
        category = "payload"
        
    strings:
        $mf1 = "dmaaqrcqphy0d"
        $mf2 = "hyewxkvve9m42"
        $mf3 = "mediafire.com/folder/"
        
    condition:
        any of ($mf1, $mf2) or ($mf3 and any of ($mf1, $mf2))
}

rule Known_Phishing_Sites
{
    meta:
        description = "Known phishing sites from this campaign"
        author = "Security Research"
        severity = "CRITICAL"
        category = "phishing"
        
    strings:
        $phish1 = "dfhawkops-aimass1sttool.github.io"
        $phish2 = "sites.google.com/view/github-launcher"
        
    condition:
        any of them
}

// ============================================================================
// REPOSITORY NAME PATTERNS
// ============================================================================

rule Suspicious_Repository_Names
{
    meta:
        description = "Suspicious repository naming patterns"
        author = "Security Research"
        severity = "MEDIUM"
        category = "naming"
        
    strings:
        // Common malware repo naming patterns
        $name1 = "delta-force-hack" nocase
        $name2 = "deltaforce-hack" nocase
        $name3 = "Delta-Force-Hack" nocase
        $name4 = /delta.*force.*\d{4}/i
        $name5 = /deltaforce.*hack.*suite/i
        $name6 = /delta.*force.*trainer/i
        $name7 = /delta.*force.*aimbot/i
        $name8 = /delta.*force.*esp/i
        $name9 = /delta.*force.*wallhack/i
        $name10 = /delta.*force.*cheat/i
        
        // Generic suspicious patterns
        $generic1 = /.*hack.*tool.*/i
        $generic2 = /.*cheat.*engine.*/i
        $generic3 = /.*mod.*menu.*/i
        $generic4 = /.*elite.*hack.*/i
        $generic5 = /.*tactical.*hack.*/i
        
    condition:
        any of them
}

// ============================================================================
// PAYLOAD CHARACTERISTICS
// ============================================================================

rule Suspicious_DLL_Names
{
    meta:
        description = "Suspicious DLL names commonly used in this campaign"
        author = "Security Research"
        severity = "HIGH"
        category = "payload"
        
    strings:
        // Legitimate Microsoft DLLs that are commonly hijacked
        $dll1 = "MSVCP140.dll"
        $dll2 = "VCRUNTIME140.dll"
        
        // Generic suspicious names
        $dll3 = "core.dll"
        $dll4 = "obsidian-source.dll"
        
        // Pattern from hantosman519 payload
        $dll5 = /base_\d+\.dll/
        $dll6 = /build_\d+\.dll/
        $dll7 = /log_\d+\.dll/
        $dll8 = /meta_\d+\.dll/
        $dll9 = /temp_\d+\.dll/
        $dll10 = /utils_\d+\.dll/
        
    condition:
        2 of them
}

rule Large_Launcher_Executable
{
    meta:
        description = "Large launcher executable (common in this campaign)"
        author = "Security Research"
        severity = "MEDIUM"
        category = "payload"
        
    strings:
        $mz = { 4D 5A }  // MZ header
        $launcher = "Launcher" nocase
        $deltaforce = "Delta" nocase
        
    condition:
        $mz at 0 and 
        filesize > 50MB and 
        any of ($launcher, $deltaforce)
}

// ============================================================================
// COMPOSITE RULES
// ============================================================================

rule Delta_Force_Malware_High_Confidence
{
    meta:
        description = "High confidence Delta Force malware detection"
        author = "Security Research"
        severity = "CRITICAL"
        
    condition:
        Cyrillic_Loader_Filename or
        Known_C2_Domains or
        (Readme_Disable_Antivirus and Readme_Bot_Generated) or
        (Readme_Fake_Verification and any of (Known_Mediafire_Payloads, Known_Phishing_Sites))
}

rule Delta_Force_Malware_Medium_Confidence
{
    meta:
        description = "Medium confidence Delta Force malware detection"
        author = "Security Research"
        severity = "HIGH"
        
    condition:
        Cyrillic_Homoglyph_General or
        (Readme_Bot_Generated and Readme_Password_Hint) or
        (Suspicious_DLL_Names and Large_Launcher_Executable)
}

