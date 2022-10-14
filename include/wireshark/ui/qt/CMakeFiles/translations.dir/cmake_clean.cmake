file(REMOVE_RECURSE
  "CMakeFiles/translations"
  "wireshark_de.qm"
  "wireshark_en.qm"
  "wireshark_es.qm"
  "wireshark_fr.qm"
  "wireshark_it.qm"
  "wireshark_ja_JP.qm"
  "wireshark_pl.qm"
  "wireshark_ru.qm"
  "wireshark_sv.qm"
  "wireshark_tr_TR.qm"
  "wireshark_uk.qm"
  "wireshark_zh_CN.qm"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/translations.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
