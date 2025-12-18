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
        description = "Detects Game Cheat repos utilizing 'Current Year' social engineering (e.g., Hack 2025)"
        author = "Security Research"
        severity = "MEDIUM"
        category = "naming"
        version = "2.1"

    strings:
        // ====================================================================
        // 1. DELTA FORCE (Base Pattern Reference)
        // ====================================================================
        // Desen: Delta Force 2025, Delta-Force-Hack-2024, DeltaForce2025
        $df_year_mix    = /delta[-_\s]*force.*?\d{4}/i
        $df_hawk_year   = /hawk[-_\s]*ops.*?\d{4}/i

        // ====================================================================
        // 2. CALL OF DUTY SERIES (BO6, BO7, MW3, Warzone) + YEAR
        // ====================================================================
        // Desen: "Black Ops 6 2025", "Warzone-Unlocker-2024", "MW3 2025"
        
        // Black Ops (6, 7 and Generic) with Year
        $cod_bo_year    = /black[-_\s]*ops[-_\s]*(6|7).*?\d{4}/i
        $cod_bo_gen     = /black[-_\s]*ops.*?\d{4}/i
        
        // Warzone with Year
        $cod_wz_year    = /warzone.*?\d{4}/i
        $cod_wz_hack_yr = /warzone.*(hack|cheat|unlock|aim).*?\d{4}/i
        
        // Modern Warfare 3 with Year
        $cod_mw3_year   = /modern[-_\s]*warfare[-_\s]*3.*?\d{4}/i
        $cod_mw_gen     = /modern[-_\s]*warfare.*?\d{4}/i
        $cod_mw3_sh_yr  = /mw3.*?\d{4}/i
        
        // General COD
        $cod_gen_year   = /call[-_\s]*of[-_\s]*duty.*?\d{4}/i
        $cod_sh_year    = /cod.*?\d{4}/i

        // ====================================================================
        // 3. COUNTER-STRIKE (CS2, CS:GO) + YEAR
        // ====================================================================
        // Desen: "CS2 2025", "Counter-Strike 2 Hack 2024"
        
        $cs2_year       = /counter[-_\s]*strike[-_\s]*2.*?\d{4}/i
        $cs2_short_yr   = /cs[-_\s]*2.*?\d{4}/i
        
        $csgo_year      = /global[-_\s]*offensive.*?\d{4}/i
        $csgo_short_yr  = /cs[-_\s]*go.*?\d{4}/i
        
        // Generic "CS Hack 2025"
        $cs_gen_yr      = /cs.*hack.*?\d{4}/i

        // ====================================================================
        // 4. BATTLEFIELD SERIES + YEAR
        // ====================================================================
        // Desen: "Battlefield V 2025", "BF2042 Hack 2025"
        // Not: BF2042 oyunun kendisi olduğu için, 2042 harici yılları veya "hack" kelimesini arıyoruz.
        
        $bf_v_year      = /battlefield[-_\s]*(v|5).*?\d{4}/i
        $bf_2042_hack   = /battlefield[-_\s]*2042.*(hack|cheat|aim).*?\d{4}/i
        $bf_gen_year    = /battlefield.*?\d{4}/i
        $bf_short_year  = /bf[-_\s]*(v|5|2042).*?\d{4}/i

        // ====================================================================
        // 5. ARMA SERIES + YEAR
        // ====================================================================
        // Desen: "Arma 3 2025", "Arma 4 2025", "Arma Reforger 2025"
        
        $arma_3_year    = /arma[-_\s]*3.*?\d{4}/i
        $arma_4_year    = /arma[-_\s]*4.*?\d{4}/i
        $arma_ref_year  = /arma[-_\s]*reforger.*?\d{4}/i
        $arma_tac_year  = /arma[-_\s]*tactics.*?\d{4}/i
        $arma_gen_year  = /arma.*(hack|cheat|script).*?\d{4}/i

        // ====================================================================
        // 6. VALORANT & WARFRAME & OUTLAST + YEAR
        // ====================================================================
        // Desen: "Valorant-2025", "Warframe Platinum 2025"
        
        // Valorant
        $val_year       = /valorant.*?\d{4}/i
        $val_hack_yr    = /valorant.*(hack|aim|esp|tpm).*?\d{4}/i
        
        // Warframe
        $wf_year        = /warframe.*?\d{4}/i
        $wf_plat_yr     = /warframe.*(plat|gold|hack).*?\d{4}/i
        
        // The Outlast
        $out_year       = /the[-_\s]*outlast.*?\d{4}/i
        $out_tr_year    = /outlast.*trainer.*?\d{4}/i

        // ====================================================================
        // 7. RUST + YEAR
        // ====================================================================
        // Desen: "Rust Script 2025", "Rust Aimbot 2024"
        // Rust dilinden ayırmak için "Hack/Cheat" kelimesi veya yılın bitişik kullanımı
        
        $rust_year      = /rust[-_\s]*\d{4}/i  // Rust2025
        $rust_scr_yr    = /rust.*script.*?\d{4}/i
        $rust_hack_yr   = /rust.*(hack|cheat|esp|recoil).*?\d{4}/i

        // ====================================================================
        // 8. COMBINATIONS (Joined/Separated)
        // ====================================================================
        // Bu kısım "GameName2025" gibi bitişik yazımları garanti altına alır
        
        $join_cod       = /cod\d{4}/i
        $join_mw3       = /mw3\d{4}/i
        $join_bo6       = /bo6\d{4}/i
        $join_cs2       = /cs2\d{4}/i
        $join_val       = /valorant\d{4}/i
        $join_arma      = /arma\d{4}/i
        
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

