﻿
Процедура ПриЗаписи(Отказ)
	
	//Найти дефолтную часть расписания
	//--------------------------------
	Запрос = Новый Запрос();
	Запрос.Текст =
	"ВЫБРАТЬ
	|	schedules_default.Ссылка КАК Ссылка
	|ИЗ
	|	ВнешнийИсточникДанных.AsteriskEdge.Таблица.schedules_default КАК schedules_default
	|ГДЕ
	|	schedules_default.id_name = &id_name";
	Запрос.УстановитьПараметр("id_name", ЭтотОбъект.id);
	РезультатЗапроса = Запрос.Выполнить();
	
	//Если нет дефолтной части - создай
	Если РезультатЗапроса.Пустой() Тогда
		Для Сч = 1 По 7 Цикл
			Об = ВнешниеИсточникиДанных.AsteriskEdge.Таблицы.schedules_default.СоздатьОбъект();
			Об.id_name = ЭтотОбъект.id;
			Об.dow = Строка(Сч);
			Попытка
				Об.Записать();
			Исключение
				ЗаписьЖурналаРегистрации("schedules_names.При записи", УровеньЖурналаРегистрации.Ошибка,, ЭтотОбъект.id, ОписаниеОшибки());
			КонецПопытки;
		КонецЦикла;
	КонецЕсли;
КонецПроцедуры

Процедура ПриКопировании(ОбъектКопирования)
	//Назначь новый id
	//-----------------
	Запрос = Новый Запрос();
	Запрос.Текст =
	"ВЫБРАТЬ
	|	МАКСИМУМ(schedules_names.id)+1 КАК id_plus_1
	|ИЗ
	|	ВнешнийИсточникДанных.AsteriskEdge.Таблица.schedules_names КАК schedules_names";
	РезультатЗапроса = Запрос.Выполнить();
	Выборка = РезультатЗапроса.Выбрать();
	Выборка.Следующий();
	ЭтотОбъект.id = Выборка.id_plus_1;
	
	//Скопируй старое дефолтное расписание в новое
	//--------------------------------------------
	//Запрос = Новый Запрос();
	//Запрос.Текст =
	//"ВЫБРАТЬ
	//|	schedules_default.dow КАК dow,
	//|	schedules_default.start_time КАК start_time,
	//|	schedules_default.end_time КАК end_time,
	//|	schedules_default.holiday КАК holiday
	//|ИЗ
	//|	ВнешнийИсточникДанных.AsteriskEdge.Таблица.schedules_default КАК schedules_default
	//|ГДЕ
	//|	schedules_default.id_name = &id_name";
	//Запрос.УстановитьПараметр("id_name", ОбъектКопирования.id);
	//РезультатЗапроса = Запрос.Выполнить();
	//Выборка = РезультатЗапроса.Выбрать();
	//Пока Выборка.Следующий() Цикл
	//		Об = ВнешниеИсточникиДанных.AsteriskEdge.Таблицы.schedules_default.СоздатьОбъект();
	//		Об.id_name = ЭтотОбъект.id;
	//		ЗаполнитьЗначенияСвойств(Об, Выборка, "dow, start_time, end_time, holiday");
	//		Попытка
	//			Об.Записать();
	//		Исключение
	//			ЗаписьЖурналаРегистрации("schedules_names.При записи", УровеньЖурналаРегистрации.Ошибка,, ЭтотОбъект.id, ОписаниеОшибки());
	//		КонецПопытки;	
	//КонецЦикла;
КонецПроцедуры
