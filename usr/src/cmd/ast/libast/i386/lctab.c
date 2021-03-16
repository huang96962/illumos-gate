/* : : generated by cmd/ast/tools/lcgen : : */

#include "lclib.h"
#include "lclang.h"


const Lc_attribute_t attribute_es[] =
{
{"traditional",LC_default,
#ifdef SUBLANG_SPANISH_TRADITIONAL
SUBLANG_SPANISH_TRADITIONAL,
#else
0,
#endif

},
{"modern",0,
#ifdef SUBLANG_SPANISH_MODERN
SUBLANG_SPANISH_MODERN,
#else
0,
#endif

},
};

const Lc_charset_t lc_charsets[] =
{
{"iso8859-1","latin1|west-europe","1252",},
{"iso8859-2","latin2|east-europe","1250",},
{"iso8859-3","latin3|south-europe","1257",},
{"iso8859-4","latin4|north-europe",0},
{"iso8859-5","cyrillic","1251",},
{"iso8859-6","arabic","1256",},
{"iso8859-7","greek","1253",},
{"iso8859-8","hebrew","1255",},
{"iso8859-9","latin5|turkish","1254",},
{"iso8859-10","latin6|nordic",0},
{"iso8859-13","latin7",0},
{"iso8859-14","latin8|celtic",0},
{"iso8859-15","latin0",0},
{"iso2022","japanese|korean",0},
{"iso4873","japanese-ascii|korean-ascii",0},
{"koi8-r","russian",0},
{"utf8","plan9",0},
	0
};

const Lc_language_t lc_languages[] =
{
{"C","C","POSIX",&lc_charsets[0],LC_default,0,0,0,},
{"debug","debug",0,&lc_charsets[0],LC_debug,0,0,0,},
{"aa","afar",0,&lc_charsets[0],0,
#ifdef LANG_AFAR
LANG_AFAR,
#else
0,
#endif
0,0,
},
{"ab","abkhazian",0,&lc_charsets[0],0,
#ifdef LANG_ABKHAZIAN
LANG_ABKHAZIAN,
#else
0,
#endif
0,0,
},
{"af","afrikaans","afr",&lc_charsets[0],0,
#ifdef LANG_AFRIKAANS
LANG_AFRIKAANS,
#else
0,
#endif
0,0,
},
{"am","amharic",0,&lc_charsets[0],0,
#ifdef LANG_AMHARIC
LANG_AMHARIC,
#else
0,
#endif
0,0,
},
{"ar","arabic","ara",&lc_charsets[5],0,
#ifdef LANG_ARABIC
LANG_ARABIC,
#else
0,
#endif
0,0,
},
{"as","assamese",0,&lc_charsets[0],0,
#ifdef LANG_ASSAMESE
LANG_ASSAMESE,
#else
0,
#endif
0,0,
},
{"ay","aymara",0,&lc_charsets[0],0,
#ifdef LANG_AYMARA
LANG_AYMARA,
#else
0,
#endif
0,0,
},
{"az","azerbaijani",0,&lc_charsets[0],0,
#ifdef LANG_AZERBAIJANI
LANG_AZERBAIJANI,
#else
0,
#endif
0,0,
},
{"ba","bashkir",0,&lc_charsets[0],0,
#ifdef LANG_BASHKIR
LANG_BASHKIR,
#else
0,
#endif
0,0,
},
{"be","belarusian","bel",&lc_charsets[0],0,
#ifdef LANG_BELARUSIAN
LANG_BELARUSIAN,
#else
0,
#endif
0,0,
},
{"bg","bulgarian","bul",&lc_charsets[4],0,
#ifdef LANG_BULGARIAN
LANG_BULGARIAN,
#else
0,
#endif
0,0,
},
{"bh","bihari",0,&lc_charsets[0],0,
#ifdef LANG_BIHARI
LANG_BIHARI,
#else
0,
#endif
0,0,
},
{"bi","bislama",0,&lc_charsets[0],0,
#ifdef LANG_BISLAMA
LANG_BISLAMA,
#else
0,
#endif
0,0,
},
{"bn","bengali-bangla",0,&lc_charsets[0],0,
#ifdef LANG_BENGALI_BANGLA
LANG_BENGALI_BANGLA,
#else
0,
#endif
0,0,
},
{"bo","tibetan",0,&lc_charsets[0],0,
#ifdef LANG_TIBETAN
LANG_TIBETAN,
#else
0,
#endif
0,0,
},
{"br","breton",0,&lc_charsets[0],0,
#ifdef LANG_BRETON
LANG_BRETON,
#else
0,
#endif
0,0,
},
{"ca","catalan","cat",&lc_charsets[0],0,
#ifdef LANG_CATALAN
LANG_CATALAN,
#else
0,
#endif
0,0,
},
{"co","corsican",0,&lc_charsets[0],0,
#ifdef LANG_CORSICAN
LANG_CORSICAN,
#else
0,
#endif
0,0,
},
{"cs","czech","ces|cze",&lc_charsets[1],0,
#ifdef LANG_CZECH
LANG_CZECH,
#else
0,
#endif
0,0,
},
{"cy","welsh",0,&lc_charsets[0],0,
#ifdef LANG_WELSH
LANG_WELSH,
#else
0,
#endif
0,0,
},
{"da","danish","dan",&lc_charsets[0],0,
#ifdef LANG_DANISH
LANG_DANISH,
#else
0,
#endif
0,0,
},
{"de","german","deu|ger",&lc_charsets[0],0,
#ifdef LANG_GERMAN
LANG_GERMAN,
#else
0,
#endif
0,0,
},
{"dz","bhutani",0,&lc_charsets[0],0,
#ifdef LANG_BHUTANI
LANG_BHUTANI,
#else
0,
#endif
0,0,
},
{"el","greek","ell|gre",&lc_charsets[6],0,
#ifdef LANG_GREEK
LANG_GREEK,
#else
0,
#endif
0,0,
},
{"en","english","eng",&lc_charsets[0],0,
#ifdef LANG_ENGLISH
LANG_ENGLISH,
#else
0,
#endif
0,0,
},
{"eo","esperanto",0,&lc_charsets[0],0,
#ifdef LANG_ESPERANTO
LANG_ESPERANTO,
#else
0,
#endif
0,0,
},
{"es","spanish","spa",&lc_charsets[0],0,
#ifdef LANG_SPANISH
LANG_SPANISH,
#else
0,
#endif
&attribute_es[0],&attribute_es[1],
},
{"et","estonian","est",&lc_charsets[2],0,
#ifdef LANG_ESTONIAN
LANG_ESTONIAN,
#else
0,
#endif
0,0,
},
{"eu","basque","eus|baq",&lc_charsets[0],0,
#ifdef LANG_BASQUE
LANG_BASQUE,
#else
0,
#endif
0,0,
},
{"fa","persian",0,&lc_charsets[0],0,
#ifdef LANG_PERSIAN
LANG_PERSIAN,
#else
0,
#endif
0,0,
},
{"fi","finnish","fin",&lc_charsets[0],0,
#ifdef LANG_FINNISH
LANG_FINNISH,
#else
0,
#endif
0,0,
},
{"fj","fiji",0,&lc_charsets[0],0,
#ifdef LANG_FIJI
LANG_FIJI,
#else
0,
#endif
0,0,
},
{"fo","faeroese",0,&lc_charsets[0],0,
#ifdef LANG_FAEROESE
LANG_FAEROESE,
#else
0,
#endif
0,0,
},
{"fr","french","fra|fre",&lc_charsets[0],0,
#ifdef LANG_FRENCH
LANG_FRENCH,
#else
0,
#endif
0,0,
},
{"fy","frisian",0,&lc_charsets[0],0,
#ifdef LANG_FRISIAN
LANG_FRISIAN,
#else
0,
#endif
0,0,
},
{"ga","irish",0,&lc_charsets[11],0,
#ifdef LANG_IRISH
LANG_IRISH,
#else
0,
#endif
0,0,
},
{"gd","scots-gaelic",0,&lc_charsets[11],0,
#ifdef LANG_SCOTS_GAELIC
LANG_SCOTS_GAELIC,
#else
0,
#endif
0,0,
},
{"gl","galician",0,&lc_charsets[0],0,
#ifdef LANG_GALICIAN
LANG_GALICIAN,
#else
0,
#endif
0,0,
},
{"gn","guarani",0,&lc_charsets[0],0,
#ifdef LANG_GUARANI
LANG_GUARANI,
#else
0,
#endif
0,0,
},
{"gu","gujarati",0,&lc_charsets[0],0,
#ifdef LANG_GUJARATI
LANG_GUJARATI,
#else
0,
#endif
0,0,
},
{"ha","hausa",0,&lc_charsets[0],0,
#ifdef LANG_HAUSA
LANG_HAUSA,
#else
0,
#endif
0,0,
},
{"he","hebrew","heb",&lc_charsets[7],0,
#ifdef LANG_HEBREW
LANG_HEBREW,
#else
0,
#endif
0,0,
},
{"hi","hindi",0,&lc_charsets[0],0,
#ifdef LANG_HINDI
LANG_HINDI,
#else
0,
#endif
0,0,
},
{"hr","croatian","hrv|scr",&lc_charsets[1],0,
#ifdef LANG_CROATIAN
LANG_CROATIAN,
#else
0,
#endif
0,0,
},
{"hu","hungarian","hun",&lc_charsets[1],0,
#ifdef LANG_HUNGARIAN
LANG_HUNGARIAN,
#else
0,
#endif
0,0,
},
{"hy","armenian",0,&lc_charsets[0],0,
#ifdef LANG_ARMENIAN
LANG_ARMENIAN,
#else
0,
#endif
0,0,
},
{"ia","interlingua",0,&lc_charsets[0],0,
#ifdef LANG_INTERLINGUA
LANG_INTERLINGUA,
#else
0,
#endif
0,0,
},
{"id","indonesian","ind",&lc_charsets[0],0,
#ifdef LANG_INDONESIAN
LANG_INDONESIAN,
#else
0,
#endif
0,0,
},
{"ie","interlingue",0,&lc_charsets[0],0,
#ifdef LANG_INTERLINGUE
LANG_INTERLINGUE,
#else
0,
#endif
0,0,
},
{"ik","inupiak",0,&lc_charsets[0],0,
#ifdef LANG_INUPIAK
LANG_INUPIAK,
#else
0,
#endif
0,0,
},
{"in","indonesian",0,&lc_charsets[0],0,
#ifdef LANG_INDONESIAN
LANG_INDONESIAN,
#else
0,
#endif
0,0,
},
{"is","icelandic","isl|ice",&lc_charsets[0],0,
#ifdef LANG_ICELANDIC
LANG_ICELANDIC,
#else
0,
#endif
0,0,
},
{"it","italian","ita",&lc_charsets[0],0,
#ifdef LANG_ITALIAN
LANG_ITALIAN,
#else
0,
#endif
0,0,
},
{"iw","hebrew",0,&lc_charsets[0],0,
#ifdef LANG_HEBREW
LANG_HEBREW,
#else
0,
#endif
0,0,
},
{"ja","japanese","jpn",&lc_charsets[0],0,
#ifdef LANG_JAPANESE
LANG_JAPANESE,
#else
0,
#endif
0,0,
},
{"ji","yiddish",0,&lc_charsets[0],0,
#ifdef LANG_YIDDISH
LANG_YIDDISH,
#else
0,
#endif
0,0,
},
{"jw","javanese",0,&lc_charsets[0],0,
#ifdef LANG_JAVANESE
LANG_JAVANESE,
#else
0,
#endif
0,0,
},
{"ka","georgian",0,&lc_charsets[0],0,
#ifdef LANG_GEORGIAN
LANG_GEORGIAN,
#else
0,
#endif
0,0,
},
{"kk","kazakh","kaz",&lc_charsets[0],0,
#ifdef LANG_KAZAKH
LANG_KAZAKH,
#else
0,
#endif
0,0,
},
{"kl","greenlandic",0,&lc_charsets[0],0,
#ifdef LANG_GREENLANDIC
LANG_GREENLANDIC,
#else
0,
#endif
0,0,
},
{"km","cambodian",0,&lc_charsets[0],0,
#ifdef LANG_CAMBODIAN
LANG_CAMBODIAN,
#else
0,
#endif
0,0,
},
{"kn","kannada",0,&lc_charsets[0],0,
#ifdef LANG_KANNADA
LANG_KANNADA,
#else
0,
#endif
0,0,
},
{"ko","korean","kor",&lc_charsets[0],0,
#ifdef LANG_KOREAN
LANG_KOREAN,
#else
0,
#endif
0,0,
},
{"ks","kashmiri",0,&lc_charsets[0],0,
#ifdef LANG_KASHMIRI
LANG_KASHMIRI,
#else
0,
#endif
0,0,
},
{"ku","kurdish",0,&lc_charsets[0],0,
#ifdef LANG_KURDISH
LANG_KURDISH,
#else
0,
#endif
0,0,
},
{"ky","kirghiz",0,&lc_charsets[0],0,
#ifdef LANG_KIRGHIZ
LANG_KIRGHIZ,
#else
0,
#endif
0,0,
},
{"la","latin",0,&lc_charsets[0],0,
#ifdef LANG_LATIN
LANG_LATIN,
#else
0,
#endif
0,0,
},
{"ln","lingala",0,&lc_charsets[0],0,
#ifdef LANG_LINGALA
LANG_LINGALA,
#else
0,
#endif
0,0,
},
{"lo","laothian",0,&lc_charsets[0],0,
#ifdef LANG_LAOTHIAN
LANG_LAOTHIAN,
#else
0,
#endif
0,0,
},
{"lt","lithuanian","lit",&lc_charsets[10],0,
#ifdef LANG_LITHUANIAN
LANG_LITHUANIAN,
#else
0,
#endif
0,0,
},
{"lv","latvian","lav",&lc_charsets[10],0,
#ifdef LANG_LATVIAN
LANG_LATVIAN,
#else
0,
#endif
0,0,
},
{"mg","malagasy",0,&lc_charsets[0],0,
#ifdef LANG_MALAGASY
LANG_MALAGASY,
#else
0,
#endif
0,0,
},
{"mi","maori",0,&lc_charsets[0],0,
#ifdef LANG_MAORI
LANG_MAORI,
#else
0,
#endif
0,0,
},
{"mk","macedonian","mkd|mac",&lc_charsets[0],0,
#ifdef LANG_MACEDONIAN
LANG_MACEDONIAN,
#else
0,
#endif
0,0,
},
{"ml","malayalam","mal",&lc_charsets[0],0,
#ifdef LANG_MALAYALAM
LANG_MALAYALAM,
#else
0,
#endif
0,0,
},
{"mn","mongolian",0,&lc_charsets[0],0,
#ifdef LANG_MONGOLIAN
LANG_MONGOLIAN,
#else
0,
#endif
0,0,
},
{"mo","moldavian",0,&lc_charsets[0],0,
#ifdef LANG_MOLDAVIAN
LANG_MOLDAVIAN,
#else
0,
#endif
0,0,
},
{"mr","marathi",0,&lc_charsets[0],0,
#ifdef LANG_MARATHI
LANG_MARATHI,
#else
0,
#endif
0,0,
},
{"ms","malay","msa|may",&lc_charsets[0],0,
#ifdef LANG_MALAY
LANG_MALAY,
#else
0,
#endif
0,0,
},
{"mt","maltese",0,&lc_charsets[0],0,
#ifdef LANG_MALTESE
LANG_MALTESE,
#else
0,
#endif
0,0,
},
{"my","burmese",0,&lc_charsets[0],0,
#ifdef LANG_BURMESE
LANG_BURMESE,
#else
0,
#endif
0,0,
},
{"na","nauru",0,&lc_charsets[0],0,
#ifdef LANG_NAURU
LANG_NAURU,
#else
0,
#endif
0,0,
},
{"nb","norwegian-bokmal","nob",&lc_charsets[0],0,
#ifdef LANG_NORWEGIAN_BOKMAL
LANG_NORWEGIAN_BOKMAL,
#else
0,
#endif
0,0,
},
{"ne","nepali",0,&lc_charsets[0],0,
#ifdef LANG_NEPALI
LANG_NEPALI,
#else
0,
#endif
0,0,
},
{"nl","dutch","nld|dut",&lc_charsets[0],0,
#ifdef LANG_DUTCH
LANG_DUTCH,
#else
0,
#endif
0,0,
},
{"nn","norwegian-nynorsk","nno|non",&lc_charsets[0],0,
#ifdef LANG_NORWEGIAN_NYNORSK
LANG_NORWEGIAN_NYNORSK,
#else
0,
#endif
0,0,
},
{"no","norwegian","nor",&lc_charsets[0],0,
#ifdef LANG_NORWEGIAN
LANG_NORWEGIAN,
#else
0,
#endif
0,0,
},
{"oc","occitan",0,&lc_charsets[0],0,
#ifdef LANG_OCCITAN
LANG_OCCITAN,
#else
0,
#endif
0,0,
},
{"om","oromo",0,&lc_charsets[0],0,
#ifdef LANG_OROMO
LANG_OROMO,
#else
0,
#endif
0,0,
},
{"or","oriya",0,&lc_charsets[0],0,
#ifdef LANG_ORIYA
LANG_ORIYA,
#else
0,
#endif
0,0,
},
{"pa","punjabi",0,&lc_charsets[0],0,
#ifdef LANG_PUNJABI
LANG_PUNJABI,
#else
0,
#endif
0,0,
},
{"pl","polish","pol",&lc_charsets[1],0,
#ifdef LANG_POLISH
LANG_POLISH,
#else
0,
#endif
0,0,
},
{"ps","pushto",0,&lc_charsets[0],0,
#ifdef LANG_PUSHTO
LANG_PUSHTO,
#else
0,
#endif
0,0,
},
{"pt","portuguese","por",&lc_charsets[0],0,
#ifdef LANG_PORTUGUESE
LANG_PORTUGUESE,
#else
0,
#endif
0,0,
},
{"qu","quechua",0,&lc_charsets[0],0,
#ifdef LANG_QUECHUA
LANG_QUECHUA,
#else
0,
#endif
0,0,
},
{"rm","rhaeto-romance",0,&lc_charsets[0],0,
#ifdef LANG_RHAETO_ROMANCE
LANG_RHAETO_ROMANCE,
#else
0,
#endif
0,0,
},
{"rn","kirundi",0,&lc_charsets[0],0,
#ifdef LANG_KIRUNDI
LANG_KIRUNDI,
#else
0,
#endif
0,0,
},
{"ro","romanian","ron|rum",&lc_charsets[1],0,
#ifdef LANG_ROMANIAN
LANG_ROMANIAN,
#else
0,
#endif
0,0,
},
{"ru","russian","rus",&lc_charsets[4],0,
#ifdef LANG_RUSSIAN
LANG_RUSSIAN,
#else
0,
#endif
0,0,
},
{"rw","kinyarwanda",0,&lc_charsets[0],0,
#ifdef LANG_KINYARWANDA
LANG_KINYARWANDA,
#else
0,
#endif
0,0,
},
{"sa","sanskrit",0,&lc_charsets[0],0,
#ifdef LANG_SANSKRIT
LANG_SANSKRIT,
#else
0,
#endif
0,0,
},
{"sd","sindhi",0,&lc_charsets[0],0,
#ifdef LANG_SINDHI
LANG_SINDHI,
#else
0,
#endif
0,0,
},
{"sg","sangro",0,&lc_charsets[0],0,
#ifdef LANG_SANGRO
LANG_SANGRO,
#else
0,
#endif
0,0,
},
{"sh","serbo-croatian",0,&lc_charsets[0],0,
#ifdef LANG_SERBO_CROATIAN
LANG_SERBO_CROATIAN,
#else
0,
#endif
0,0,
},
{"si","singhalese",0,&lc_charsets[0],0,
#ifdef LANG_SINGHALESE
LANG_SINGHALESE,
#else
0,
#endif
0,0,
},
{"sk","slovak","slk|slo",&lc_charsets[1],0,
#ifdef LANG_SLOVAK
LANG_SLOVAK,
#else
0,
#endif
0,0,
},
{"sl","slovenian","slv",&lc_charsets[1],0,
#ifdef LANG_SLOVENIAN
LANG_SLOVENIAN,
#else
0,
#endif
0,0,
},
{"sm","samoan",0,&lc_charsets[0],0,
#ifdef LANG_SAMOAN
LANG_SAMOAN,
#else
0,
#endif
0,0,
},
{"sn","shona",0,&lc_charsets[0],0,
#ifdef LANG_SHONA
LANG_SHONA,
#else
0,
#endif
0,0,
},
{"so","somali",0,&lc_charsets[0],0,
#ifdef LANG_SOMALI
LANG_SOMALI,
#else
0,
#endif
0,0,
},
{"sq","albanian","sqi|alb",&lc_charsets[0],0,
#ifdef LANG_ALBANIAN
LANG_ALBANIAN,
#else
0,
#endif
0,0,
},
{"sr","serbian","srp",&lc_charsets[1],0,
#ifdef LANG_SERBIAN
LANG_SERBIAN,
#else
0,
#endif
0,0,
},
{"ss","siswati",0,&lc_charsets[0],0,
#ifdef LANG_SISWATI
LANG_SISWATI,
#else
0,
#endif
0,0,
},
{"st","sesotho",0,&lc_charsets[0],0,
#ifdef LANG_SESOTHO
LANG_SESOTHO,
#else
0,
#endif
0,0,
},
{"su","sudanese",0,&lc_charsets[0],0,
#ifdef LANG_SUDANESE
LANG_SUDANESE,
#else
0,
#endif
0,0,
},
{"sv","swedish","swe",&lc_charsets[0],0,
#ifdef LANG_SWEDISH
LANG_SWEDISH,
#else
0,
#endif
0,0,
},
{"sw","swahili","swa",&lc_charsets[0],0,
#ifdef LANG_SWAHILI
LANG_SWAHILI,
#else
0,
#endif
0,0,
},
{"ta","tamil",0,&lc_charsets[0],0,
#ifdef LANG_TAMIL
LANG_TAMIL,
#else
0,
#endif
0,0,
},
{"te","telugu",0,&lc_charsets[0],0,
#ifdef LANG_TELUGU
LANG_TELUGU,
#else
0,
#endif
0,0,
},
{"tg","tajik",0,&lc_charsets[0],0,
#ifdef LANG_TAJIK
LANG_TAJIK,
#else
0,
#endif
0,0,
},
{"th","thai","tha",&lc_charsets[0],0,
#ifdef LANG_THAI
LANG_THAI,
#else
0,
#endif
0,0,
},
{"ti","tigrinya",0,&lc_charsets[0],0,
#ifdef LANG_TIGRINYA
LANG_TIGRINYA,
#else
0,
#endif
0,0,
},
{"tk","turkmen",0,&lc_charsets[0],0,
#ifdef LANG_TURKMEN
LANG_TURKMEN,
#else
0,
#endif
0,0,
},
{"tl","tagalog",0,&lc_charsets[0],0,
#ifdef LANG_TAGALOG
LANG_TAGALOG,
#else
0,
#endif
0,0,
},
{"tn","setswana",0,&lc_charsets[0],0,
#ifdef LANG_SETSWANA
LANG_SETSWANA,
#else
0,
#endif
0,0,
},
{"to","tonga",0,&lc_charsets[0],0,
#ifdef LANG_TONGA
LANG_TONGA,
#else
0,
#endif
0,0,
},
{"tr","turkish","tur",&lc_charsets[8],0,
#ifdef LANG_TURKISH
LANG_TURKISH,
#else
0,
#endif
0,0,
},
{"ts","tsonga",0,&lc_charsets[0],0,
#ifdef LANG_TSONGA
LANG_TSONGA,
#else
0,
#endif
0,0,
},
{"tt","tatar","tat",&lc_charsets[0],0,
#ifdef LANG_TATAR
LANG_TATAR,
#else
0,
#endif
0,0,
},
{"tw","chinese-traditional","cht",&lc_charsets[0],0,
#ifdef LANG_CHINESE_TRADITIONAL
LANG_CHINESE_TRADITIONAL,
#else
0,
#endif
0,0,
},
{"uk","ukrainian","ukr",&lc_charsets[4],0,
#ifdef LANG_UKRAINIAN
LANG_UKRAINIAN,
#else
0,
#endif
0,0,
},
{"ur","urdu",0,&lc_charsets[0],0,
#ifdef LANG_URDU
LANG_URDU,
#else
0,
#endif
0,0,
},
{"uz","uzbek","uzb",&lc_charsets[0],0,
#ifdef LANG_UZBEK
LANG_UZBEK,
#else
0,
#endif
0,0,
},
{"vi","vietnamese",0,&lc_charsets[0],0,
#ifdef LANG_VIETNAMESE
LANG_VIETNAMESE,
#else
0,
#endif
0,0,
},
{"vo","volapuk",0,&lc_charsets[0],0,
#ifdef LANG_VOLAPUK
LANG_VOLAPUK,
#else
0,
#endif
0,0,
},
{"wo","wolof",0,&lc_charsets[0],0,
#ifdef LANG_WOLOF
LANG_WOLOF,
#else
0,
#endif
0,0,
},
{"xh","xhosa",0,&lc_charsets[0],0,
#ifdef LANG_XHOSA
LANG_XHOSA,
#else
0,
#endif
0,0,
},
{"yo","yoruba",0,&lc_charsets[0],0,
#ifdef LANG_YORUBA
LANG_YORUBA,
#else
0,
#endif
0,0,
},
{"zh","chinese-simplified","zho|chi|chs",&lc_charsets[0],0,
#ifdef LANG_CHINESE_SIMPLIFIED
LANG_CHINESE_SIMPLIFIED,
#else
0,
#endif
0,0,
},
{"zu","zulu",0,&lc_charsets[0],0,
#ifdef LANG_ZULU
LANG_ZULU,
#else
0,
#endif
0,0,
},
	0
};

const Lc_territory_t lc_territories[] =
{
{"C","C",LC_default,0,&lc_languages[0],0,0,0,0,0,0,0,},
{"debug","debug",LC_debug,0,&lc_languages[1],0,0,0,0,0,0,0,},
{"eu","euro",0,0,&lc_languages[0],0,0,0,0,0,0,0,},
{"al","albania",0,
#ifdef CTRY_ALBANIA
CTRY_ALBANIA,
#else
0,
#endif
0,0,0,0,0,0,0,0,
},
{"an","netherlands-antilles",0,
#ifdef CTRY_NETHERLANDS_ANTILLES
CTRY_NETHERLANDS_ANTILLES,
#else
0,
#endif
&lc_languages[86],0,0,0,
#ifdef SUBLANG_DUTCH_NETHERLANDS_ANTILLES
SUBLANG_DUTCH_NETHERLANDS_ANTILLES,
#else
0,
#endif
0,0,0,
},
{"ar","argentina",0,
#ifdef CTRY_ARGENTINA
CTRY_ARGENTINA,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_ARGENTINA
SUBLANG_SPANISH_ARGENTINA,
#else
0,
#endif
0,0,0,
},
{"at","austria",0,
#ifdef CTRY_AUSTRIA
CTRY_AUSTRIA,
#else
0,
#endif
&lc_languages[23],0,0,0,
#ifdef SUBLANG_GERMAN_AUSTRIA
SUBLANG_GERMAN_AUSTRIA,
#else
0,
#endif
0,0,0,
},
{"au","australia",0,
#ifdef CTRY_AUSTRALIA
CTRY_AUSTRALIA,
#else
0,
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_AUSTRALIA
SUBLANG_ENGLISH_AUSTRALIA,
#else
0,
#endif
0,0,0,
},
{"az","azerbaijan",0,
#ifdef CTRY_AZERBAIJAN
CTRY_AZERBAIJAN,
#else
0,
#endif
0,0,0,0,0,0,0,0,
},
{"be","belgium",0,
#ifdef CTRY_BELGIUM
CTRY_BELGIUM,
#else
0,
#endif
&lc_languages[86],&lc_languages[35],&lc_languages[23],0,
#ifdef SUBLANG_DUTCH_BELGIUM
SUBLANG_DUTCH_BELGIUM,
#else
0,
#endif

#ifdef SUBLANG_FRENCH_BELGIUM
SUBLANG_FRENCH_BELGIUM,
#else
0,
#endif

#ifdef SUBLANG_GERMAN_BELGIUM
SUBLANG_GERMAN_BELGIUM,
#else
0,
#endif
0,
},
{"bg","bulgaria",0,
#ifdef CTRY_BULGARIA
CTRY_BULGARIA,
#else
0,
#endif
&lc_languages[12],0,0,0,
#ifdef SUBLANG_BULGARIAN_BULGARIA
SUBLANG_BULGARIAN_BULGARIA,
#else
0,
#endif
0,0,0,
},
{"bn","brunei-darussalam",0,
#ifdef CTRY_BRUNEI_DARUSSALAM
CTRY_BRUNEI_DARUSSALAM,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_BRUNEI_DARUSSALAM
SUBLANG_ARABIC_BRUNEI_DARUSSALAM,
#else
0,
#endif
0,0,0,
},
{"bo","bolivia",0,
#ifdef CTRY_BOLIVIA
CTRY_BOLIVIA,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_BOLIVIA
SUBLANG_SPANISH_BOLIVIA,
#else
0,
#endif
0,0,0,
},
{"br","brazil",0,
#ifdef CTRY_BRAZIL
CTRY_BRAZIL,
#else
0,
#endif
&lc_languages[95],0,0,0,
#ifdef SUBLANG_PORTUGUESE_BRAZIL
SUBLANG_PORTUGUESE_BRAZIL,
#else
0,
#endif
0,0,0,
},
{"bw","botswana",0,
#ifdef CTRY_BOTSWANA
CTRY_BOTSWANA,
#else
0,
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_BOTSWANA
SUBLANG_ENGLISH_BOTSWANA,
#else
0,
#endif
0,0,0,
},
{"by","belarus",0,
#ifdef CTRY_BELARUS
CTRY_BELARUS,
#else
0,
#endif
&lc_languages[100],0,0,0,
#ifdef SUBLANG_RUSSIAN_BELARUS
SUBLANG_RUSSIAN_BELARUS,
#else
0,
#endif
0,0,0,
},
{"bz","belize",0,
#ifdef CTRY_BELIZE
CTRY_BELIZE,
#else
0,
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_BELIZE
SUBLANG_ENGLISH_BELIZE,
#else
0,
#endif
0,0,0,
},
{"ca","canada",0,
#ifdef CTRY_CANADA
CTRY_CANADA,
#else
0,
#endif
&lc_languages[26],&lc_languages[35],0,0,
#ifdef SUBLANG_ENGLISH_CANADA
SUBLANG_ENGLISH_CANADA,
#else
0,
#endif

#ifdef SUBLANG_FRENCH_CANADA
SUBLANG_FRENCH_CANADA,
#else
0,
#endif
0,0,
},
{"ch","switzerland",0,
#ifdef CTRY_SWITZERLAND
CTRY_SWITZERLAND,
#else
0,
#endif
&lc_languages[35],&lc_languages[23],&lc_languages[54],0,
#ifdef SUBLANG_FRENCH_SWITZERLAND
SUBLANG_FRENCH_SWITZERLAND,
#else
0,
#endif

#ifdef SUBLANG_GERMAN_SWITZERLAND
SUBLANG_GERMAN_SWITZERLAND,
#else
0,
#endif

#ifdef SUBLANG_ITALIAN_SWITZERLAND
SUBLANG_ITALIAN_SWITZERLAND,
#else
0,
#endif
0,
},
{"cl","chile",0,
#ifdef CTRY_CHILE
CTRY_CHILE,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_CHILE
SUBLANG_SPANISH_CHILE,
#else
0,
#endif
0,0,0,
},
{"cn","china",LC_primary,
#ifdef CTRY_CHINA
CTRY_CHINA,
#else
0,
#endif
&lc_languages[140],0,0,0,
#ifdef SUBLANG_CHINESE_SIMPLIFIED_CHINA
SUBLANG_CHINESE_SIMPLIFIED_CHINA,
#else
0,
#endif
0,0,0,
},
{"co","colombia",0,
#ifdef CTRY_COLOMBIA
CTRY_COLOMBIA,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_COLOMBIA
SUBLANG_SPANISH_COLOMBIA,
#else
0,
#endif
0,0,0,
},
{"cr","costa-rica",0,
#ifdef CTRY_COSTA_RICA
CTRY_COSTA_RICA,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_COSTA_RICA
SUBLANG_SPANISH_COSTA_RICA,
#else
0,
#endif
0,0,0,
},
{"cz","czech-republic",0,
#ifdef CTRY_CZECH_REPUBLIC
CTRY_CZECH_REPUBLIC,
#else
0,
#endif
&lc_languages[20],0,0,0,
#ifdef SUBLANG_CZECH_CZECH_REPUBLIC
SUBLANG_CZECH_CZECH_REPUBLIC,
#else
0,
#endif
0,0,0,
},
{"de","germany",0,
#ifdef CTRY_GERMANY
CTRY_GERMANY,
#else
0,
#endif
&lc_languages[23],0,0,0,
#ifdef SUBLANG_GERMAN_GERMANY
SUBLANG_GERMAN_GERMANY,
#else
0,
#endif
0,0,0,
},
{"dk","denmark",0,
#ifdef CTRY_DENMARK
CTRY_DENMARK,
#else
0,
#endif
&lc_languages[22],&lc_languages[26],0,0,
#ifdef SUBLANG_DANISH_DENMARK
SUBLANG_DANISH_DENMARK,
#else
0,
#endif

#ifdef SUBLANG_ENGLISH_DENMARK
SUBLANG_ENGLISH_DENMARK,
#else
0,
#endif
0,0,
},
{"do","dominican-republic",0,
#ifdef CTRY_DOMINICAN_REPUBLIC
CTRY_DOMINICAN_REPUBLIC,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_DOMINICAN_REPUBLIC
SUBLANG_SPANISH_DOMINICAN_REPUBLIC,
#else
0,
#endif
0,0,0,
},
{"dz","algeria",0,
#ifdef CTRY_ALGERIA
CTRY_ALGERIA,
#else
0,
#endif
0,0,0,0,0,0,0,0,
},
{"ec","ecuador",0,
#ifdef CTRY_ECUADOR
CTRY_ECUADOR,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_ECUADOR
SUBLANG_SPANISH_ECUADOR,
#else
0,
#endif
0,0,0,
},
{"ee","estonia",0,
#ifdef CTRY_ESTONIA
CTRY_ESTONIA,
#else
0,
#endif
&lc_languages[29],0,0,0,
#ifdef SUBLANG_ESTONIAN_ESTONIA
SUBLANG_ESTONIAN_ESTONIA,
#else
0,
#endif
0,0,0,
},
{"eg","egypt",0,
#ifdef CTRY_EGYPT
CTRY_EGYPT,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_EGYPT
SUBLANG_ARABIC_EGYPT,
#else
0,
#endif
0,0,0,
},
{"es","spain",0,
#ifdef CTRY_SPAIN
CTRY_SPAIN,
#else
0,
#endif
&lc_languages[28],&lc_languages[18],&lc_languages[30],&lc_languages[39],
#ifdef SUBLANG_SPANISH_SPAIN
SUBLANG_SPANISH_SPAIN,
#else
0,
#endif

#ifdef SUBLANG_CATALAN_SPAIN
SUBLANG_CATALAN_SPAIN,
#else
0,
#endif

#ifdef SUBLANG_BASQUE_SPAIN
SUBLANG_BASQUE_SPAIN,
#else
0,
#endif

#ifdef SUBLANG_GALICIAN_SPAIN
SUBLANG_GALICIAN_SPAIN,
#else
0,
#endif

},
{"fi","finland",0,
#ifdef CTRY_FINLAND
CTRY_FINLAND,
#else
0,
#endif
&lc_languages[117],0,0,0,
#ifdef SUBLANG_SWEDISH_FINLAND
SUBLANG_SWEDISH_FINLAND,
#else
0,
#endif
0,0,0,
},
{"fo","faroe-islands",0,
#ifdef CTRY_FAROE_ISLANDS
CTRY_FAROE_ISLANDS,
#else
0,
#endif
&lc_languages[34],0,0,0,
#ifdef SUBLANG_FAEROESE_FAROE_ISLANDS
SUBLANG_FAEROESE_FAROE_ISLANDS,
#else
0,
#endif
0,0,0,
},
{"fr","france",0,
#ifdef CTRY_FRANCE
CTRY_FRANCE,
#else
0,
#endif
&lc_languages[35],0,0,0,
#ifdef SUBLANG_FRENCH_FRANCE
SUBLANG_FRENCH_FRANCE,
#else
0,
#endif
0,0,0,
},
{"gb","united-kingdom|great-britain|england",LC_primary,
#ifdef CTRY_UNITED_KINGDOM
CTRY_UNITED_KINGDOM,
#else
#ifdef CTRY_GREAT_BRITAIN
CTRY_GREAT_BRITAIN,
#else
#ifdef CTRY_ENGLAND
CTRY_ENGLAND,
#else
0,
#endif
#endif
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_UNITED_KINGDOM
SUBLANG_ENGLISH_UNITED_KINGDOM,
#else
#ifdef SUBLANG_ENGLISH_GREAT_BRITAIN
SUBLANG_ENGLISH_GREAT_BRITAIN,
#else
#ifdef SUBLANG_ENGLISH_ENGLAND
SUBLANG_ENGLISH_ENGLAND,
#else
0,
#endif
#endif
#endif
0,0,0,
},
{"gl","greenland",0,
#ifdef CTRY_GREENLAND
CTRY_GREENLAND,
#else
0,
#endif
&lc_languages[61],0,0,0,
#ifdef SUBLANG_GREENLANDIC_GREENLAND
SUBLANG_GREENLANDIC_GREENLAND,
#else
0,
#endif
0,0,0,
},
{"gr","greece",0,
#ifdef CTRY_GREECE
CTRY_GREECE,
#else
0,
#endif
&lc_languages[25],0,0,0,
#ifdef SUBLANG_GREEK_GREECE
SUBLANG_GREEK_GREECE,
#else
0,
#endif
0,0,0,
},
{"gt","guatemala",0,
#ifdef CTRY_GUATEMALA
CTRY_GUATEMALA,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_GUATEMALA
SUBLANG_SPANISH_GUATEMALA,
#else
0,
#endif
0,0,0,
},
{"hk","hong-kong",0,
#ifdef CTRY_HONG_KONG
CTRY_HONG_KONG,
#else
0,
#endif
&lc_languages[140],0,0,0,
#ifdef SUBLANG_CHINESE_SIMPLIFIED_HONG_KONG
SUBLANG_CHINESE_SIMPLIFIED_HONG_KONG,
#else
0,
#endif
0,0,0,
},
{"hn","honduras",0,
#ifdef CTRY_HONDURAS
CTRY_HONDURAS,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_HONDURAS
SUBLANG_SPANISH_HONDURAS,
#else
0,
#endif
0,0,0,
},
{"hr","croatia",0,
#ifdef CTRY_CROATIA
CTRY_CROATIA,
#else
0,
#endif
&lc_languages[45],0,0,0,
#ifdef SUBLANG_CROATIAN_CROATIA
SUBLANG_CROATIAN_CROATIA,
#else
0,
#endif
0,0,0,
},
{"hu","hungary",0,
#ifdef CTRY_HUNGARY
CTRY_HUNGARY,
#else
0,
#endif
&lc_languages[46],0,0,0,
#ifdef SUBLANG_HUNGARIAN_HUNGARY
SUBLANG_HUNGARIAN_HUNGARY,
#else
0,
#endif
0,0,0,
},
{"id","indonesia",0,
#ifdef CTRY_INDONESIA
CTRY_INDONESIA,
#else
0,
#endif
&lc_languages[49],0,0,0,
#ifdef SUBLANG_INDONESIAN_INDONESIA
SUBLANG_INDONESIAN_INDONESIA,
#else
0,
#endif
0,0,0,
},
{"ie","ireland",0,
#ifdef CTRY_IRELAND
CTRY_IRELAND,
#else
0,
#endif
&lc_languages[26],&lc_languages[37],0,0,
#ifdef SUBLANG_ENGLISH_IRELAND
SUBLANG_ENGLISH_IRELAND,
#else
0,
#endif

#ifdef SUBLANG_IRISH_IRELAND
SUBLANG_IRISH_IRELAND,
#else
0,
#endif
0,0,
},
{"il","israel",0,
#ifdef CTRY_ISRAEL
CTRY_ISRAEL,
#else
0,
#endif
&lc_languages[43],0,0,0,
#ifdef SUBLANG_HEBREW_ISRAEL
SUBLANG_HEBREW_ISRAEL,
#else
0,
#endif
0,0,0,
},
{"iq","iraq",0,
#ifdef CTRY_IRAQ
CTRY_IRAQ,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_IRAQ
SUBLANG_ARABIC_IRAQ,
#else
0,
#endif
0,0,0,
},
{"is","iceland",0,
#ifdef CTRY_ICELAND
CTRY_ICELAND,
#else
0,
#endif
&lc_languages[53],0,0,0,
#ifdef SUBLANG_ICELANDIC_ICELAND
SUBLANG_ICELANDIC_ICELAND,
#else
0,
#endif
0,0,0,
},
{"it","italy",0,
#ifdef CTRY_ITALY
CTRY_ITALY,
#else
0,
#endif
&lc_languages[54],0,0,0,
#ifdef SUBLANG_ITALIAN_ITALY
SUBLANG_ITALIAN_ITALY,
#else
0,
#endif
0,0,0,
},
{"jm","jamaica",0,
#ifdef CTRY_JAMAICA
CTRY_JAMAICA,
#else
0,
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_JAMAICA
SUBLANG_ENGLISH_JAMAICA,
#else
0,
#endif
0,0,0,
},
{"jo","jordan",0,
#ifdef CTRY_JORDAN
CTRY_JORDAN,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_JORDAN
SUBLANG_ARABIC_JORDAN,
#else
0,
#endif
0,0,0,
},
{"jp","japan",0,
#ifdef CTRY_JAPAN
CTRY_JAPAN,
#else
0,
#endif
&lc_languages[56],0,0,0,
#ifdef SUBLANG_JAPANESE_JAPAN
SUBLANG_JAPANESE_JAPAN,
#else
0,
#endif
0,0,0,
},
{"ke","kenya",0,
#ifdef CTRY_KENYA
CTRY_KENYA,
#else
0,
#endif
0,0,0,0,0,0,0,0,
},
{"kr","south-korea",0,
#ifdef CTRY_SOUTH_KOREA
CTRY_SOUTH_KOREA,
#else
0,
#endif
&lc_languages[64],0,0,0,
#ifdef SUBLANG_KOREAN_SOUTH_KOREA
SUBLANG_KOREAN_SOUTH_KOREA,
#else
0,
#endif
0,0,0,
},
{"kw","kuwait",0,
#ifdef CTRY_KUWAIT
CTRY_KUWAIT,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_KUWAIT
SUBLANG_ARABIC_KUWAIT,
#else
0,
#endif
0,0,0,
},
{"lb","lebanon",0,
#ifdef CTRY_LEBANON
CTRY_LEBANON,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_LEBANON
SUBLANG_ARABIC_LEBANON,
#else
0,
#endif
0,0,0,
},
{"li","liechtenstein",0,
#ifdef CTRY_LIECHTENSTEIN
CTRY_LIECHTENSTEIN,
#else
0,
#endif
&lc_languages[23],&lc_languages[35],0,0,
#ifdef SUBLANG_GERMAN_LIECHTENSTEIN
SUBLANG_GERMAN_LIECHTENSTEIN,
#else
0,
#endif

#ifdef SUBLANG_FRENCH_LIECHTENSTEIN
SUBLANG_FRENCH_LIECHTENSTEIN,
#else
0,
#endif
0,0,
},
{"lt","lithuania",0,
#ifdef CTRY_LITHUANIA
CTRY_LITHUANIA,
#else
0,
#endif
&lc_languages[71],0,0,0,
#ifdef SUBLANG_LITHUANIAN_LITHUANIA
SUBLANG_LITHUANIAN_LITHUANIA,
#else
0,
#endif
0,0,0,
},
{"lu","luxembourg",0,
#ifdef CTRY_LUXEMBOURG
CTRY_LUXEMBOURG,
#else
0,
#endif
&lc_languages[23],&lc_languages[35],0,0,
#ifdef SUBLANG_GERMAN_LUXEMBOURG
SUBLANG_GERMAN_LUXEMBOURG,
#else
0,
#endif

#ifdef SUBLANG_FRENCH_LUXEMBOURG
SUBLANG_FRENCH_LUXEMBOURG,
#else
0,
#endif
0,0,
},
{"lv","latvia",0,
#ifdef CTRY_LATVIA
CTRY_LATVIA,
#else
0,
#endif
&lc_languages[72],0,0,0,
#ifdef SUBLANG_LATVIAN_LATVIA
SUBLANG_LATVIAN_LATVIA,
#else
0,
#endif
0,0,0,
},
{"ly","libya",0,
#ifdef CTRY_LIBYA
CTRY_LIBYA,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_LIBYA
SUBLANG_ARABIC_LIBYA,
#else
0,
#endif
0,0,0,
},
{"ma","morocco",0,
#ifdef CTRY_MOROCCO
CTRY_MOROCCO,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_MOROCCO
SUBLANG_ARABIC_MOROCCO,
#else
0,
#endif
0,0,0,
},
{"mk","macedonia",0,
#ifdef CTRY_MACEDONIA
CTRY_MACEDONIA,
#else
0,
#endif
&lc_languages[75],0,0,0,
#ifdef SUBLANG_MACEDONIAN_MACEDONIA
SUBLANG_MACEDONIAN_MACEDONIA,
#else
0,
#endif
0,0,0,
},
{"mo","macau",0,
#ifdef CTRY_MACAU
CTRY_MACAU,
#else
0,
#endif
&lc_languages[140],0,0,0,
#ifdef SUBLANG_CHINESE_SIMPLIFIED_MACAU
SUBLANG_CHINESE_SIMPLIFIED_MACAU,
#else
0,
#endif
0,0,0,
},
{"mx","mexico",0,
#ifdef CTRY_MEXICO
CTRY_MEXICO,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_MEXICO
SUBLANG_SPANISH_MEXICO,
#else
0,
#endif
0,0,0,
},
{"my","malaysia",0,
#ifdef CTRY_MALAYSIA
CTRY_MALAYSIA,
#else
0,
#endif
0,0,0,0,0,0,0,0,
},
{"ni","nicaragua",0,
#ifdef CTRY_NICARAGUA
CTRY_NICARAGUA,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_NICARAGUA
SUBLANG_SPANISH_NICARAGUA,
#else
0,
#endif
0,0,0,
},
{"nl","netherlands",0,
#ifdef CTRY_NETHERLANDS
CTRY_NETHERLANDS,
#else
0,
#endif
&lc_languages[86],0,0,0,
#ifdef SUBLANG_DUTCH_NETHERLANDS
SUBLANG_DUTCH_NETHERLANDS,
#else
0,
#endif
0,0,0,
},
{"no","norway",0,
#ifdef CTRY_NORWAY
CTRY_NORWAY,
#else
0,
#endif
&lc_languages[84],&lc_languages[88],&lc_languages[87],0,
#ifdef SUBLANG_NORWEGIAN_BOKMAL_NORWAY
SUBLANG_NORWEGIAN_BOKMAL_NORWAY,
#else
0,
#endif

#ifdef SUBLANG_NORWEGIAN_NORWAY
SUBLANG_NORWEGIAN_NORWAY,
#else
0,
#endif

#ifdef SUBLANG_NORWEGIAN_NYNORSK_NORWAY
SUBLANG_NORWEGIAN_NYNORSK_NORWAY,
#else
0,
#endif
0,
},
{"nz","new-zealand",0,
#ifdef CTRY_NEW_ZEALAND
CTRY_NEW_ZEALAND,
#else
0,
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_NEW_ZEALAND
SUBLANG_ENGLISH_NEW_ZEALAND,
#else
0,
#endif
0,0,0,
},
{"om","oman",0,
#ifdef CTRY_OMAN
CTRY_OMAN,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_OMAN
SUBLANG_ARABIC_OMAN,
#else
0,
#endif
0,0,0,
},
{"pa","panama",0,
#ifdef CTRY_PANAMA
CTRY_PANAMA,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_PANAMA
SUBLANG_SPANISH_PANAMA,
#else
0,
#endif
0,0,0,
},
{"pe","peru",0,
#ifdef CTRY_PERU
CTRY_PERU,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_PERU
SUBLANG_SPANISH_PERU,
#else
0,
#endif
0,0,0,
},
{"pl","poland",0,
#ifdef CTRY_POLAND
CTRY_POLAND,
#else
0,
#endif
&lc_languages[93],0,0,0,
#ifdef SUBLANG_POLISH_POLAND
SUBLANG_POLISH_POLAND,
#else
0,
#endif
0,0,0,
},
{"pr","puerto-rico",0,
#ifdef CTRY_PUERTO_RICO
CTRY_PUERTO_RICO,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_PUERTO_RICO
SUBLANG_SPANISH_PUERTO_RICO,
#else
0,
#endif
0,0,0,
},
{"pt","portugal",0,
#ifdef CTRY_PORTUGAL
CTRY_PORTUGAL,
#else
0,
#endif
&lc_languages[95],0,0,0,
#ifdef SUBLANG_PORTUGUESE_PORTUGAL
SUBLANG_PORTUGUESE_PORTUGAL,
#else
0,
#endif
0,0,0,
},
{"py","paraguay",0,
#ifdef CTRY_PARAGUAY
CTRY_PARAGUAY,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_PARAGUAY
SUBLANG_SPANISH_PARAGUAY,
#else
0,
#endif
0,0,0,
},
{"ro","romania",0,
#ifdef CTRY_ROMANIA
CTRY_ROMANIA,
#else
0,
#endif
&lc_languages[99],0,0,0,
#ifdef SUBLANG_ROMANIAN_ROMANIA
SUBLANG_ROMANIAN_ROMANIA,
#else
0,
#endif
0,0,0,
},
{"ru","russia",0,
#ifdef CTRY_RUSSIA
CTRY_RUSSIA,
#else
0,
#endif
&lc_languages[100],0,0,0,
#ifdef SUBLANG_RUSSIAN_RUSSIA
SUBLANG_RUSSIAN_RUSSIA,
#else
0,
#endif
0,0,0,
},
{"sa","saudi-arabia",0,
#ifdef CTRY_SAUDI_ARABIA
CTRY_SAUDI_ARABIA,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_SAUDI_ARABIA
SUBLANG_ARABIC_SAUDI_ARABIA,
#else
0,
#endif
0,0,0,
},
{"se","sweden",LC_primary,
#ifdef CTRY_SWEDEN
CTRY_SWEDEN,
#else
0,
#endif
&lc_languages[117],0,0,0,
#ifdef SUBLANG_SWEDISH_SWEDEN
SUBLANG_SWEDISH_SWEDEN,
#else
0,
#endif
0,0,0,
},
{"sg","singapore",0,
#ifdef CTRY_SINGAPORE
CTRY_SINGAPORE,
#else
0,
#endif
&lc_languages[140],0,0,0,
#ifdef SUBLANG_CHINESE_SIMPLIFIED_SINGAPORE
SUBLANG_CHINESE_SIMPLIFIED_SINGAPORE,
#else
0,
#endif
0,0,0,
},
{"si","slovenia",0,
#ifdef CTRY_SLOVENIA
CTRY_SLOVENIA,
#else
0,
#endif
&lc_languages[108],0,0,0,
#ifdef SUBLANG_SLOVENIAN_SLOVENIA
SUBLANG_SLOVENIAN_SLOVENIA,
#else
0,
#endif
0,0,0,
},
{"sk","slovakia",0,
#ifdef CTRY_SLOVAKIA
CTRY_SLOVAKIA,
#else
0,
#endif
&lc_languages[107],0,0,0,
#ifdef SUBLANG_SLOVAK_SLOVAKIA
SUBLANG_SLOVAK_SLOVAKIA,
#else
0,
#endif
0,0,0,
},
{"sp","serbia",0,
#ifdef CTRY_SERBIA
CTRY_SERBIA,
#else
0,
#endif
&lc_languages[113],0,0,0,
#ifdef SUBLANG_SERBIAN_SERBIA
SUBLANG_SERBIAN_SERBIA,
#else
0,
#endif
0,0,0,
},
{"sv","el-salvador",0,
#ifdef CTRY_EL_SALVADOR
CTRY_EL_SALVADOR,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_EL_SALVADOR
SUBLANG_SPANISH_EL_SALVADOR,
#else
0,
#endif
0,0,0,
},
{"sy","syria",0,
#ifdef CTRY_SYRIA
CTRY_SYRIA,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_SYRIA
SUBLANG_ARABIC_SYRIA,
#else
0,
#endif
0,0,0,
},
{"th","thailand",0,
#ifdef CTRY_THAILAND
CTRY_THAILAND,
#else
0,
#endif
&lc_languages[122],0,0,0,
#ifdef SUBLANG_THAI_THAILAND
SUBLANG_THAI_THAILAND,
#else
0,
#endif
0,0,0,
},
{"tn","tunisia",0,
#ifdef CTRY_TUNISIA
CTRY_TUNISIA,
#else
0,
#endif
&lc_languages[6],0,0,0,
#ifdef SUBLANG_ARABIC_TUNISIA
SUBLANG_ARABIC_TUNISIA,
#else
0,
#endif
0,0,0,
},
{"tr","turkey",0,
#ifdef CTRY_TURKEY
CTRY_TURKEY,
#else
0,
#endif
&lc_languages[128],0,0,0,
#ifdef SUBLANG_TURKISH_TURKEY
SUBLANG_TURKISH_TURKEY,
#else
0,
#endif
0,0,0,
},
{"tt","trinidad&tobago",0,
#ifdef CTRY_TRINIDAD_TOBAGO
CTRY_TRINIDAD_TOBAGO,
#else
0,
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_TRINIDAD_TOBAGO
SUBLANG_ENGLISH_TRINIDAD_TOBAGO,
#else
0,
#endif
0,0,0,
},
{"tw","taiwan",0,
#ifdef CTRY_TAIWAN
CTRY_TAIWAN,
#else
0,
#endif
&lc_languages[131],0,0,0,
#ifdef SUBLANG_CHINESE_TRADITIONAL_TAIWAN
SUBLANG_CHINESE_TRADITIONAL_TAIWAN,
#else
0,
#endif
0,0,0,
},
{"ua","ukraine",0,
#ifdef CTRY_UKRAINE
CTRY_UKRAINE,
#else
0,
#endif
&lc_languages[132],&lc_languages[100],0,0,
#ifdef SUBLANG_UKRAINIAN_UKRAINE
SUBLANG_UKRAINIAN_UKRAINE,
#else
0,
#endif

#ifdef SUBLANG_RUSSIAN_UKRAINE
SUBLANG_RUSSIAN_UKRAINE,
#else
0,
#endif
0,0,
},
{"uk","united-kingdom",LC_primary,
#ifdef CTRY_UNITED_KINGDOM
CTRY_UNITED_KINGDOM,
#else
0,
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_UNITED_KINGDOM
SUBLANG_ENGLISH_UNITED_KINGDOM,
#else
0,
#endif
0,0,0,
},
{"us","united-states|usa",0,
#ifdef CTRY_UNITED_STATES
CTRY_UNITED_STATES,
#else
#ifdef CTRY_USA
CTRY_USA,
#else
0,
#endif
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_UNITED_STATES
SUBLANG_ENGLISH_UNITED_STATES,
#else
#ifdef SUBLANG_ENGLISH_USA
SUBLANG_ENGLISH_USA,
#else
0,
#endif
#endif
0,0,0,
},
{"uy","uruguay",0,
#ifdef CTRY_URUGUAY
CTRY_URUGUAY,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_URUGUAY
SUBLANG_SPANISH_URUGUAY,
#else
0,
#endif
0,0,0,
},
{"ve","venezuela",0,
#ifdef CTRY_VENEZUELA
CTRY_VENEZUELA,
#else
0,
#endif
&lc_languages[28],0,0,0,
#ifdef SUBLANG_SPANISH_VENEZUELA
SUBLANG_SPANISH_VENEZUELA,
#else
0,
#endif
0,0,0,
},
{"yu","yugoslavia",0,
#ifdef CTRY_YUGOSLAVIA
CTRY_YUGOSLAVIA,
#else
0,
#endif
&lc_languages[113],0,0,0,
#ifdef SUBLANG_SERBIAN_YUGOSLAVIA
SUBLANG_SERBIAN_YUGOSLAVIA,
#else
0,
#endif
0,0,0,
},
{"za","south-africa",0,
#ifdef CTRY_SOUTH_AFRICA
CTRY_SOUTH_AFRICA,
#else
0,
#endif
&lc_languages[4],0,0,0,
#ifdef SUBLANG_AFRIKAANS_SOUTH_AFRICA
SUBLANG_AFRIKAANS_SOUTH_AFRICA,
#else
0,
#endif
0,0,0,
},
{"zw","zimbabwe",0,
#ifdef CTRY_ZIMBABWE
CTRY_ZIMBABWE,
#else
0,
#endif
&lc_languages[26],0,0,0,
#ifdef SUBLANG_ENGLISH_ZIMBABWE
SUBLANG_ENGLISH_ZIMBABWE,
#else
0,
#endif
0,0,0,
},
	0
};

const Lc_map_t lc_maps[] =
{
{"enu",&lc_languages[26],&lc_territories[94],&lc_charsets[0],0},
{"enz",&lc_languages[26],&lc_territories[69],&lc_charsets[0],0},
{"esm",&lc_languages[28],&lc_territories[64],&lc_charsets[0],0},
{"esn",&lc_languages[28],&lc_territories[31],&lc_charsets[0],&attribute_es[1]},
{"esp",&lc_languages[28],&lc_territories[31],&lc_charsets[0],&attribute_es[0]},
{"usa",&lc_languages[26],&lc_territories[94],&lc_charsets[0],0},
	0
};
