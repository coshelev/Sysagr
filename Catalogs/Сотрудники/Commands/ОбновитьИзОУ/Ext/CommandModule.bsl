﻿
&НаКлиенте
Процедура ОбработкаКоманды(ПараметрКоманды, ПараметрыВыполненияКоманды);
	ТекстДок= Новый ТекстовыйДокумент();
	ОбщегоНазначения.СотрудникиОУ_Загрузить(ТекстДок);
	Если ТекстДок.КоличествоСтрок()>0 Тогда
		ТекстДок.Показать("Новые сотрудники");
		ПараметрыВыполненияКоманды.Источник.ОбновитьОтображениеДанных();
	Иначе
		сообщить("Новых сотрудников нет");
	КонецЕсли;
КонецПроцедуры
