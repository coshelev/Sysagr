﻿
&НаКлиенте
Процедура НавСсылкаНажатие(Элемент, СтандартнаяОбработка)
	ПерейтиПоНавСсылке()
КонецПроцедуры

&НаКлиенте
Процедура НаименованиеНажатие(Элемент, СтандартнаяОбработка)
	ПерейтиПоНавСсылке()
КонецПроцедуры

&НаКлиенте
Процедура ПерейтиПоНавСсылке()
	АбсСсылка = "https://mainiis/asc_oper/#"+ЭтаФорма.Объект.НавСсылка;
	ПерейтиПоНавигационнойСсылке(АбсСсылка);	
КонецПроцедуры
