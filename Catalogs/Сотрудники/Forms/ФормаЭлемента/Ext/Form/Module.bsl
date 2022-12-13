﻿

&НаКлиенте
Процедура Представление_в_Идентификатор(Команда)	
	СформироватьКлюч_длиной_N(1);
КонецПроцедуры

&НаКлиенте 
Процедура СформироватьКлюч_длиной_N(КоличествоКлючей)
	
	ТекДанные = ЭтаФорма.Элементы.КлючиВИсточникахДанных.ТекущиеДанные;
	Если ТекДанные = Неопределено Тогда
		Возврат
	КонецЕсли;
	
	Для Сч = 1 По КоличествоКлючей Цикл
		
		//Если ключ не составной, т.е. количество ключей равно единице
		//------------------------------------------------------------
		Если КоличествоКлючей = 1 Тогда
			НомерКлюча = "";  // цикл будет выполнен один раз
		Иначе
			НомерКлюча=Сч;
		КонецЕсли;
		
		//Определи названия реквизитов
		//------------------------------
		ИмяРеквТипКлюча					=	"ТипКлюча"+НомерКлюча;		
		ИмяРеквЗначениеКлюча			=	"ЗначениеКлюча"+НомерКлюча;
		ИмяРеквПредставлениеКлюча		=	"ПредставлениеКлюча"+НомерКлюча;
		ИмяРеквДопПредставлениеКлюча	=	"ДопПредставлениеКлюча"+НомерКлюча;	

		
		Если Не ЗначениеЗаполнено(ТекДанные.ТипКлюча)Тогда
		Сообщить("Не указан тип данных "+НомерКлюча);
			Прервать;
		КонецЕсли;
	
		Доступно = ЗначениеЗаполнено(ТекДанные[ИмяРеквПредставлениеКлюча]) Или ЗначениеЗаполнено(ТекДанные[ИмяРеквДопПредставлениеКлюча]);
		Если Не Доступно Тогда
			Сообщить("Не заполнено ни наименование, ни код для ключа "+НомерКлюча);
			Прервать;
		КонецЕсли;
					
		Если ЗначениеЗаполнено(ТекДанные[ИмяРеквДопПредставлениеКлюча]) Тогда
			ИмяРеквизитПоиска 			= "Код";
			ЗначениеРеквзитаПоиска 	= СокрЛП( ТекДанные[ИмяРеквДопПредставлениеКлюча] );

		ИначеЕсли ЗначениеЗаполнено(ТекДанные[ИмяРеквПредставлениеКлюча]) Тогда
			ИмяРеквизитПоиска 			= "Наименование";
			ЗначениеРеквзитаПоиска 	= СокрЛП( ТекДанные[ИмяРеквПредставлениеКлюча] );
		КонецЕсли;
		
		Представление_в_Идентификатор_НаСервере(ТекДанные["НомерСтроки"], НомерКлюча, ТекДанные[ИмяРеквТипКлюча], ИмяРеквизитПоиска, ЗначениеРеквзитаПоиска);
		
	КонецЦикла;
КонецПроцедуры

&НаСервере
Процедура Представление_в_Идентификатор_НаСервере(НомерСтроки, НомерКлюча, ТипДанных, ИмяРеквизита, ЗначениеРеквизита)

	Об = РеквизитФормыВЗначение("Объект");
	//Об.Реквизит_в_Идентификатор(НомерСтроки, НомерКлюча,ТипДанных, ИмяРеквизита, ЗначениеРеквизита);
	КонсолидацияСервер.Реквизит_в_Идентификатор(Об, "КлючиВИсточникахДанных",НомерСтроки, НомерКлюча,ТипДанных, ИмяРеквизита, ЗначениеРеквизита);

	Если Об.Модифицированность() Тогда
		ЭтаФорма.Модифицированность = Истина;
	КонецЕсли;
	
	ЗначениеВРеквизитФормы(Об, "Объект");
	
КонецПроцедуры

&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	
	////Сформируй представление из ссылки для руководителя сотрудника
	////------------------------------------------------------------------------------------------------
	//Если ЗначениеЗаполнено(ЭтаФорма.Объект.Руководитель) Тогда
	//	ЭтаФорма.РуководительПредставление = СотрудникГУИДвПредставление(ЭтаФорма.Объект.Руководитель);	
	//КонецЕсли;
	//
	////Сформируй представление из ссылки для целевой точки
	////------------------------------------------------------------------------------------------------
	//Если ЗначениеЗаполнено(ЭтаФорма.Объект.ЦелеваяТочка) Тогда
	//	ЭтаФорма.ЦелеваяТочкаПредставление = ЦелеваяТочкаГУИДвПредставление(ЭтаФорма.Объект.ЦелеваяТочка);	
	//КонецЕсли;
	//
	//	
	////Сформируй представление из ссылки для руководителя в истории реквизитов
	////------------------------------------------------------------------------------------------------
	//Для Каждого Стр Из ЭтаФорма.Объект.ИсторияРеквизитов Цикл	
	//	Доступно = Стр.ИмяРеквизита = "Руководитель";
	//	Доступно = Доступно И ЗначениеЗаполнено(Стр.Значение);
	//	Если Доступно Тогда
	//		Стр.Представление = СотрудникГУИДвПредставление(Стр.Значение);	
	//	КонецЕсли;
	//КонецЦикла;
	//
	////Сформируй представление из ссылки для целевой точки в истории реквизитов
	////------------------------------------------------------------------------------------------------
	//Для Каждого Стр Из ЭтаФорма.Объект.ИсторияРеквизитов Цикл	
	//	Доступно = Стр.ИмяРеквизита = "Руководитель";
	//	Доступно = Доступно И ЗначениеЗаполнено(Стр.Значение);
	//	Если Доступно Тогда
	//		Стр.Представление = СотрудникГУИДвПредставление(Стр.Значение);	
	//	КонецЕсли;
	//КонецЦикла;

КонецПроцедуры

&НаСервере
Функция СотрудникГУИДвПредставление(ГУИД)
	ЗначениеПоУмолчанию = "";
	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ ПЕРВЫЕ 1
	|	ТЧ.Ссылка.Наименование КАК ПредставлениеКлюча
	|ИЗ
	|	Справочник.Сотрудники.КлючиВИсточникахДанных КАК ТЧ
	|ГДЕ
	|	ТЧ.ЗначениеКлюча = &ЗначениеКлюча";
	Запрос.УстановитьПараметр("ЗначениеКлюча", ГУИД);
	
	Рез = Запрос.Выполнить();
	
	Если Рез.Пустой() Тогда
		Возврат ЗначениеПоУмолчанию;	
	КонецЕсли;
	
	Возврат Рез.Выгрузить()[0][0];
КонецФункции

&НаСервере
Функция ЦелеваяТочкаГУИДвПредставление(ГУИД)
	ЗначениеПоУмолчанию = "";
	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ ПЕРВЫЕ 1
	|	ТЧ.ПредставлениеКлюча КАК ПредставлениеКлюча
	|ИЗ
	|	Справочник.ТочкиЦелевые.КлючиВИсточникахДанных КАК ТЧ
	|ГДЕ
	|	ТЧ.ЗначениеКлюча = &ЗначениеКлюча";
	Запрос.УстановитьПараметр("ЗначениеКлюча", ГУИД);
	
	Рез = Запрос.Выполнить();
	
	Если Рез.Пустой() Тогда
		Возврат ЗначениеПоУмолчанию;	
	КонецЕсли;
	
	Возврат Рез.Выгрузить()[0][0];
КонецФункции

	



