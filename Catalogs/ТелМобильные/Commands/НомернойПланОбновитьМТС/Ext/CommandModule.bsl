&НаКлиенте
Процедура ОбработкаКоманды(ПараметрКоманды,ПараметрыВыполненияКоманды)
	Окно = ВариантОткрытияОкна.ОтдельноеОкно;
	Источник = ПараметрыВыполненияКоманды.Источник;
	Уникальность = ПараметрыВыполненияКоманды.Уникальность;
	НавигационнаяСсылка = ПараметрыВыполненияКоманды.НавигационнаяСсылка;
	ОткрытьФорму("Справочник.ТелМобильные.Форма.НомернойПланОбновитьМТС",,Источник,Уникальность,Окно,НавигационнаяСсылка);
КонецПроцедуры
