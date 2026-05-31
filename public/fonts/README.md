# Self-hosted fonts

## Inter Variable (`inter/InterVariable.woff2`)

- Source: <https://rsms.me/inter/font-files/InterVariable.woff2>
- License: SIL Open Font License 1.1 (<https://github.com/rsms/inter/blob/master/LICENSE.txt>)
- Re-download: `curl -sSL -o inter/InterVariable.woff2 https://rsms.me/inter/font-files/InterVariable.woff2`

## Material Symbols Rounded (`material-symbols/MaterialSymbolsRounded.woff2`)

This file is a **subset** containing only the icons referenced by the app. Full
font is ~5.3 MB; the subset is ~64 KB.

- License: Apache 2.0 (<https://github.com/google/material-design-icons/blob/master/LICENSE>)
- Subset icons (keep in sync with `public/css/base.css` and any icon used in JS):

```
add, add_circle, arrow_back, arrow_forward, brightness_auto, check,
check_circle, close, content_copy, dark_mode, dark_mode_outline, delete,
download, edit, error, expand_more, folder, format_size, groups, history,
home, info, key, light_mode, lock, login, logout, menu, menu_book, more_vert,
open_in_new, palette, password, person, person_add, radio_button_unchecked,
refresh, remove_moderator, rocket_launch, rounded_corner, save, search,
security, settings, shield, sync, upload, visibility, visibility_off, warning
```

### Re-generating the subset when new icons are added

```bash
ICONS="home lock groups settings search ..."  # full list above + any new ones
NAMES=$(echo "$ICONS" | tr ' ' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
curl -sSL "https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&icon_names=${NAMES}" \
  -H "User-Agent: Mozilla/5.0 (Linux; rv:120.0) Gecko/20100101 Firefox/120.0" \
  -o /tmp/ms.css
URL=$(grep -oP "url\(\K[^)]+" /tmp/ms.css | head -1)
curl -sSL -o material-symbols/MaterialSymbolsRounded.woff2 "$URL"
```
