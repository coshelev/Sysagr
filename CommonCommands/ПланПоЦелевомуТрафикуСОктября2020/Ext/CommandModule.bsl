
&НаКлиенте
Процедура ОбработкаКоманды(ПараметрКоманды, ПараметрыВыполненияКоманды)
	
	Парам = Новый Структура();
	Парам.Вставить("РегистрСведений", 	"УчетнаяПолитика");
	Парам.Вставить("Измерение", 		"Параметр");
	Парам.Вставить("Ресурс", 			"Значение");
	Парам.Вставить("ЗначениеИзмерения", "РостовВиктор_ПланПоЦелевомуТрафикуСОктября2020");
	
	ОткрытьФорму("Обработка.ТаблицаXML_ПланПоЦелевомуТрафикуСОктября2020.Форма.Форма", Парам);
	
КонецПроцедуры
