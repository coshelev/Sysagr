
Процедура ПередЗаписью(Отказ)
	
	Если ЭтотОбъект.ЭтоГруппа Тогда
		Возврат
	КонецЕсли;
	
	Для Каждого Стр Из ЭтотОбъект.ВариантыОтветов Цикл
		Если СтрЧислоВхождений(Стр.Ответ, "|") Тогда
			Сообщить("Ошибка записи: недопустимый символ ""|"" в ответе.");
			Отказ = Истина;
			Возврат;
		КонецЕсли;
	КонецЦикла;
	
	Если ЭтотОбъект.ВариантыОтветов.Количество()>0 Тогда
		ЕстьДублиВВариантахОтветов = ЕстьДублиВВариантахОтветов(ЭтотОбъект.ВариантыОтветов);
		Если ЗначениеЗаполнено(ЕстьДублиВВариантахОтветов) Тогда
			Сообщить(ЕстьДублиВВариантахОтветов);
			Отказ = Истина;
			Возврат;
		КонецЕсли;
	КонецЕсли;

	ЭтотОбъект.МодифицированнаяСтрока = Конвертация.МодифицироватьСтроку(ЭтотОбъект.Наименование);
	
	//Запись  истории изменения вопроса
	//----------------------------------
	НоваяЗапись = ЭтотОбъект.ИсторияВопроса.Добавить();
	НоваяЗапись.Период = ТекущаяДата();
	НоваяЗапись.ТекстВопроса = ЭтотОбъект.Наименование;
	
	// Запись ответов в справочник Идентификаторы строк
	//--------------------------------------------------
	Для Каждого Стр Из ЭтотОбъект.ВариантыОтветов Цикл
		ИдСтрокиОтвета  = Справочники.ИдентификаторыСтрок.УстановиИдентификаторСтроки(Стр.Ответ, "ответ", Стр.Ответ, Стр.Характеристика);
	КонецЦикла;
КонецПроцедуры

Функция ЕстьДублиВВариантахОтветов(ВариантыОтветов)
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	АнкетыВариантыОтветов.Ответ КАК Ответ
	|ПОМЕСТИТЬ АнкетыВариантыОтветов
	|ИЗ
	|	&АнкетыВариантыОтветов КАК АнкетыВариантыОтветов
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	АнкетыВариантыОтветов.Ответ КАК Ответ,
	|	СУММА(1) КАК Поле1
	|ИЗ
	|	АнкетыВариантыОтветов КАК АнкетыВариантыОтветов
	|
	|СГРУППИРОВАТЬ ПО
	|	АнкетыВариантыОтветов.Ответ
	|
	|ИМЕЮЩИЕ
	|	СУММА(1) > 1";
	Запрос.УстановитьПараметр("АнкетыВариантыОтветов", ВариантыОтветов);
	РезультатЗапроса = Запрос.Выполнить();
	Если РезультатЗапроса.Пустой() Тогда
		Возврат ""
	КонецЕсли;
	
	Возврат "Есть дубли в ответах: "+ СтрСоединить(РезультатЗапроса.Выгрузить().ВыгрузитьКолонку(0), "; ");
КонецФункции

