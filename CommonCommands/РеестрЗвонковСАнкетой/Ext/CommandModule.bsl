﻿&НаКлиенте
Процедура ОбработкаКоманды(ПараметрКоманды,ПараметрыВыполненияКоманды)
	Источник = ПараметрыВыполненияКоманды.Источник;
	Уникальность = ПараметрыВыполненияКоманды.Уникальность;
	НавигационнаяСсылка = ПараметрыВыполненияКоманды.НавигационнаяСсылка;
	ОткрытьФорму("РегистрСведений.Звонки.Форма.ФормаСпискаСАнкетой",,Источник,Уникальность,,НавигационнаяСсылка);
КонецПроцедуры
