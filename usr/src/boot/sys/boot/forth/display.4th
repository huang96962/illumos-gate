: set-mode-1024
  s" 1024x768" s" set" 2 framebuffer
;

: framebuffer-on
  ['] set-mode-1024 catch drop
  s" boot/fonts/12x24b.fnt" 1 loadfont
;

: framebuffer-big
  ['] set-mode-1024 catch drop
;

: framebuffer-off
  s" off" 1 framebuffer
  loadfont
;

: load-small-font
  s" boot/fonts/6x12.fnt" 1 loadfont
;

: init-display
  s" 7" s" tem.fg_color" setenv
  s" 0" s" tem.bg_color" setenv
  framebuffer-on
;

: init-font ( -- )
  s" boot_kmdb" getenv dup -1 <> if
    s" YES" compare-insensitive 0= if
      framebuffer-big
      load-small-font
      exit
    then
  else
    drop
  then
  framebuffer-off
;

set loader_menu_title=${loader_title}

: get-w ( -- pos-w )
  1024 s" screen-width" getenvn ( -- scr-w )
  8 -                           ( -- pos-w )
;

: get-h ( -- pos-h )
  768 s" screen-height" getenvn ( -- scr-h )
  12 -                          ( -- pos-h )
;

: getx2 ( png-w -- x2 )
  1024 s" screen-width" getenvn ( png-w -- png-w scr-w )
  \ x2=png-w*scr-w/1024
  * 1024 /                      ( png-w scr-w -- x2 )
;

: gety2 ( png-h -- y2 )
  768 s" screen-height" getenvn ( png-h -- png-h scr-h )
  * 768 /                       ( png-h scr-h -- y2 )
;

: get-png ( -- loader_png )
  s" loader_png" getenv
;

: get-png-args ( -- 0 x1 y1 x2 y2 png )
  0 8 0 get-w get-h get-png
;
