
&НаКлиенте
Процедура СтрПриСменеСтраницы(Элемент, ТекущаяСтраница)
	Если ТекущаяСтраница.Имя = "СтрГрафик" Тогда
		ПокажиГрафик(ЭтаФорма.ТаблДок);
	КонецЕсли;
	Если ТекущаяСтраница.Имя = "СтрГуглГрафик" Тогда
		тз = ПокажиГуглГрафик(ЭтаФорма.ТаблДок);
		ЭтаФорма.текстHTML=тз;
	КонецЕсли;
КонецПроцедуры

&НаСервере
Процедура ПокажиГрафик(ТаблДок)
	ТаблДок.Очистить();
	Об = РеквизитФормыВЗначение("Объект");
	Об.ПостройГрафик(ТаблДок);	
КонецПроцедуры

&НаСервере
Функция ПокажиГуглГрафик(ТаблДок)
	ТаблДок.Очистить();
	Об = РеквизитФормыВЗначение("Объект");
	тз = Об.ПодготовьГуглГрафик(ТаблДок);
	Возврат тз;
КонецФункции

