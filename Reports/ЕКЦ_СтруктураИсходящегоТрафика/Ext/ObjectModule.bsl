﻿Процедура ПриКомпоновкеРезультата(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка)
	ПараметрыДанных = КомпоновщикНастроек.Настройки.ПараметрыДанных;
	ПараметрыДанных.УстановитьЗначениеПараметра("Начало", 		Период.ДатаНачала);
	ПараметрыДанных.УстановитьЗначениеПараметра("Окончание", 	Период.ДатаОкончания);
	ПараметрыДанных.УстановитьЗначениеПараметра("КЦСсылка", 	Справочники.Предприятие.НайтиПоКоду("000000265"));
КонецПроцедуры

