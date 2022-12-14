&НаСервере
Процедура ПриСозданииНаСервере(Отказ,СтандартнаяОбработка)

// Линейный элемент справочника не может находиться вне группы
//-------------------------------------------------------------------------------------------------
	Если (НЕ ЗначениеЗаполнено(Объект.Родитель)) Тогда
		Сообщение = Новый СообщениеПользователю;
		Сообщение.Текст = "Целевая точка должена обязательно принадлежать группе";
		Сообщение.Сообщить();
		Отказ = Истина;
	КонецЕсли;
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура НадписьГрафикРаботыНажатие(Элемент)
	Если (ЗначениеЗаполнено(Объект.Ссылка)) Тогда
		СтрПараметры = Новый Структура("ОбъектСсылка",Объект.Ссылка);
		ОткрытьФорму("Справочник.ГрафикиРаботы.Форма.ОбъектГрафикРаботы",СтрПараметры);
	КонецЕсли;
КонецПроцедуры

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


