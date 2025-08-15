=== WP Security Guardian ===
Contributors: securityguardian
Tags: security, plugins, whitelist, protection, admin
Requires at least: 5.0
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Bezpečnostní plugin, který řídí aktivaci dalších pluginů prostřednictvím whitelistu. Zabraňuje neautorizované aktivaci pluginů nahrání hackery.

== Description ==

WP Security Guardian je pokročilý bezpečnostní plugin navržený k ochraně vašeho WordPress webu před neautorizovanou aktivací pluginů. 

**Hlavní funkce:**

* **Whitelist System** - Pouze povolené pluginy mohou být aktivovány
* **FTP Protection** - Zabraňuje aktivaci pluginů nahraných přes FTP bez autorizace
* **Modern UI** - Krásné, moderní rozhraní s Tailwind CSS
* **Bulk Actions** - Hromadné povolování/zakazování pluginů
* **Export/Import** - Zálohování a obnovení nastavení
* **Real-time Stats** - Živé statistiky povolených/blokovaných pluginů
* **Search & Filter** - Rychlé vyhledávání v seznamu pluginů

**Jak to funguje:**

1. Plugin vytvoří whitelist povolených pluginů
2. Při pokusu o aktivaci zkontroluje, zda je plugin na whitelistu
3. Pokud není, aktivace je zablokována
4. Administrátor může spravovat whitelist přes admin rozhraní

**Bezpečnostní výhody:**

* Ochrana před malware pluginy
* Kontrola nad tím, které pluginy mohou běžet
* Prevence před neautorizovanými změnami
* Audit trail všech povolených pluginů

== Installation ==

1. Nahrajte plugin do `/wp-content/plugins/wp-security-guardian/` adresáře
2. Aktivujte plugin v admin panelu
3. Přejděte do Nastavení > Security Guardian
4. Vyberte pluginy, které chcete povolit
5. Uložte nastavení

== Frequently Asked Questions ==

= Co se stane, když deaktivuji Security Guardian? =

Při deaktivaci se vypne bezpečnostní ochrana, ale nastavení zůstanou zachována. Můžete plugin znovu aktivovat kdykoli.

= Mohu exportovat svá nastavení? =

Ano, plugin podporuje export a import nastavení ve formátu JSON.

= Funguje to s multisite? =

Momentálně je plugin navržen pro single-site instalace. Multisite podpora bude přidána v budoucí verzi.

= Co když zapomenu povolit důležitý plugin? =

Security Guardian sám sebe nikdy neblokuje. Můžete ho vždy použít k úpravě whitelistu.

== Screenshots ==

1. Hlavní administrační rozhraní s whitelistem pluginů
2. Statistiky a rychlé akce
3. Moderní design s Tailwind CSS
4. Export/Import funkcionalita

== Changelog ==

= 1.0.0 =
* První vydání
* Základní whitelist funkcionalita
* Moderní admin rozhraní
* Export/Import nastavení
* Hromadné akce
* Vyhledávání pluginů

== Upgrade Notice ==

= 1.0.0 =
První vydání WP Security Guardian pluginu.

== Security ==

Tento plugin je navržen s důrazem na bezpečnost:

* Všechny vstupy jsou sanitizovány
* Používá WordPress nonces pro CSRF ochranu
* Vyžaduje admin oprávnění pro všechny akce
* Neloguje žádné citlivé informace

== Support ==

Pro podporu a nahlášení chyb navštivte naše GitHub repository nebo kontaktujte tým přes email.

== Roadmap ==

Plánované funkce pro budoucí verze:

* Multisite podpora
* API pro externí integrace
* Pokročilejší logování
* Automatické skenování pluginů
* Integrace s bezpečnostními službami