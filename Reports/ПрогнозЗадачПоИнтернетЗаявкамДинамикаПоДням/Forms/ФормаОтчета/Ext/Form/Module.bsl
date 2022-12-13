﻿
&НаСервере
Процедура ПриЗагрузкеВариантаНаСервере(Настройки)
	ТекДата = ТекущаяДата();
	
	ТекПериод = Новый СтандартныйПериод();
	ТекПериод.ДатаНачала 	= НачалоМесяца(ТекДата);
	ТекПериод.ДатаОкончания = ТекДата;	
	ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.ПараметрыДанных.УстановитьЗначениеПараметра("Период" ,ТекПериод);
	
КонецПроцедуры

&НаКлиенте
Процедура ПриОткрытии(Отказ)
	//ЭтаФорма.СкомпоноватьРезультат();
	//ЭтаФормаРезультат);
	//ЭтаФорма.Отчет.ск
КонецПроцедуры

&НаКлиенте
Процедура ОткрытьИерархию(Команда)
	//ОткрытьФорму("ВнешнийОтчет.ПрогнозЗадачПоИнтернетЗаявкам.Форма.Иерархия");
	ОткрытьФорму("Отчет.ПрогнозЗадачПоИнтернетЗаявкам.Форма.Иерархия");
КонецПроцедуры

&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	
	//Прочитать иерархию
	//-------------------
	
	Парам = Новый Структура();
	Парам.Вставить("Отчет_ПрогнозЗадачПоИнтернетЗаявкам_Иерархия");
	РегистрыСведений.УчетнаяПолитика.Получи(Парам);
	
	Если Не ЗначениеЗаполнено(Парам["Отчет_ПрогнозЗадачПоИнтернетЗаявкам_Иерархия"]) Тогда
		Возврат
	Иначе
		ПрочитатьИерархию(Парам["Отчет_ПрогнозЗадачПоИнтернетЗаявкам_Иерархия"]);
		ЭтаФорма.отчет.ИерархияСтрокой = Парам["Отчет_ПрогнозЗадачПоИнтернетЗаявкам_Иерархия"];
	КонецЕсли;

КонецПроцедуры

&НаСервере
Функция ПрочитатьИерархию(Стр)
	ЭтаФорма.Отчет.Иерархия.Очистить();
	
	Чт = Новый ЧтениеXML();
	Чт.УстановитьСтроку(Стр);
	Постр = Новый ПостроительDOM();
	Док = Постр.Прочитать(Чт);
	
	Корень = Док.ДочерниеУзлы[0];
	Для Каждого Ряд Из Корень.ДочерниеУзлы Цикл
			Новая = ЭтаФорма.Отчет.Иерархия.Добавить();
			Новая.Группа 	= Ряд.ДочерниеУзлы[0].ДочерниеУзлы[0].ТекстовоеСодержимое;
			Новая.Сайт 		= Ряд.ДочерниеУзлы[1].ДочерниеУзлы[0].ТекстовоеСодержимое;
	КонецЦикла;
	
КонецФункции

