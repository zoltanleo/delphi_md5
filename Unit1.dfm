object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Form1'
  ClientHeight = 201
  ClientWidth = 447
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object mmo1: TMemo
    Left = 8
    Top = 8
    Width = 257
    Height = 145
    Lines.Strings = (
      'Lorem ipsum dolor sit amet, consectetur adipiscing '
      'elit. Nullam interdum elit elit, pharetra rutrum dui '
      'convallis eu. Maecenas tempus orci tincidunt '
      'sapien efficitur iaculis. Quisque gravida, nisl facilisis '
      'dapibus interdum, nunc tortor pharetra neque, '
      'bibendum pretium sem elit non purus. Maecenas '
      'libero neque, feugiat nec quam sit amet, varius '
      'lobortis lorem. Phasellus sed tristique sem. In mi '
      'ipsum, dapibus ut condimentum nec, sodales non '
      'purus. Proin semper in lorem at sodales.')
    TabOrder = 0
  end
  object btn1: TButton
    Left = 304
    Top = 16
    Width = 75
    Height = 25
    Caption = 'btn1'
    TabOrder = 1
    OnClick = btn1Click
  end
end
