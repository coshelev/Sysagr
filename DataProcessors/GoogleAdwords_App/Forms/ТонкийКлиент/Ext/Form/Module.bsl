&НаКлиенте
Процедура АвторизацияИЗагрузка_НаКлиенте()
	АвторизацияИЗагрузка_НаСервере()	
КонецПроцедуры

&НаСервере
Процедура АвторизацияИЗагрузка_НаСервере()
	Об = РеквизитФормыВЗначение("Объект");
	Об.АвторизацияБезПользователяИЗагрузка();	
КонецПроцедуры
