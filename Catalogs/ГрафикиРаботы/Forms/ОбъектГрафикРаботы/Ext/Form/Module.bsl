&НаСервере
Процедура ПриСозданииНаСервере(Отказ,СтандартнаяОбработка)

// Перенесем параметры формы в ее реквизиты
// Проверим правильность переданных параметров
//-------------------------------------------------------------------------------------------------
	ЭтаФорма.ОбъектСсылка = ЭтаФорма.Параметры.ОбъектСсылка;

	Если (НЕ ЗначениеЗаполнено(ЭтаФорма.ОбъектСсылка)) Тогда
		Возврат;
	КонецЕсли;

// Сформируем заголовок формы
//-------------------------------------------------------------------------------------------------
	Темп = "График работы для объекта (" + СокрЛП(ЭтаФорма.ОбъектСсылка.Метаданные().Синоним);
	ЭтаФорма.Заголовок = СокрЛП(Темп) + ") " + СокрЛП(ЭтаФорма.ОбъектСсылка);

// Доступность реквизита "Список"
//-------------------------------------------------------------------------------------------------
	Доступно = ПравоДоступа("Изменение",Метаданные.РегистрыСведений.ГрафикиОтклонения);
	Доступно = Доступно И ПравоДоступа("Редактирование",Метаданные.РегистрыСведений.ГрафикиОтклонения);
	Элементы.Список.ТолькоПросмотр = (НЕ Доступно);

// Доступность колонки "Локально"
//-------------------------------------------------------------------------------------------------
	Доступно = (ТипЗнч(ЭтаФорма.ОбъектСсылка) = Тип("СправочникСсылка.ТочкиЦелевые"));
	Элементы.Список.ПодчиненныеЭлементы.СписокЛокально.Видимость = Доступно;
КонецПроцедуры

&НаКлиенте
Процедура ПриОткрытии(Отказ)

// Проинициализируем Период
//-------------------------------------------------------------------------------------------------
	ЭтаФорма.Период.Вариант = ВариантСтандартногоПериода.ЭтотМесяц;
	ПериодПриИзменении();
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ПериодПриИзменении(Элемент = Неопределено)
	СписокСформировать(ТекущаяДата());
КонецПроцедуры

&НаСервере
Процедура СписокСформировать(ДатаПозиционирования)

// Заполним ТЗ "Список" сведениями о режиме работы объекта на каждый день
//-------------------------------------------------------------------------------------------------
	ТекДата = НачалоДня(ЭтаФорма.Период.ДатаНачала);
	ЭтаФорма.Список.Очистить();

	Пока (ТекДата <= ЭтаФорма.Период.ДатаОкончания) Цикл
		НовСтрока = ЭтаФорма.Список.Добавить();
		НовСтрока.ДеньНедели = СокрЛП(Конвертация.ДеньНеделиПрописью(ТекДата));
		НовСтрока.Дата = ТекДата;

// Найдем объект в регистре сведений "ГрафикиОтклонения"
//-------------------------------------------------------------------------------------------------
		ТекЗапись = РегистрыСведений.ГрафикиОтклонения.СоздатьМенеджерЗаписи();
		ТекЗапись.Объект = ЭтаФорма.ОбъектСсылка;
		ТекЗапись.Период = ТекДата;
		ТекЗапись.Прочитать();

// Если запись найдена, значит режим на этот день задан вручную и он имеет приоритет
//-------------------------------------------------------------------------------------------------
		Если (ТекЗапись.Выбран()) Тогда
			НовСтрока.НачВремя = ТекЗапись.НачВремя;
			НовСтрока.КонВремя = ТекЗапись.КонВремя;
			НовСтрока.Локально = ТекЗапись.Локально;
			НовСтрока.Режим = ТекЗапись.Режим;
			НовСтрока.Вручную = Истина;

// Если запись не найдена, то получим данные о режиме работы из графика по-умолчанию
//-------------------------------------------------------------------------------------------------
		Иначе
			СтрГрафик = ОбщегоНазначения.РежимРаботыНаДатуПолучить(ТекДата,ЭтаФорма.ОбъектСсылка);
			НовСтрока.НачВремя = СтрГрафик.НачВремя;
			НовСтрока.КонВремя = СтрГрафик.КонВремя;
			НовСтрока.Локально = СтрГрафик.Локально;
			НовСтрока.Режим = СтрГрафик.Режим;
		КонецЕсли;

		ТекДата = НачалоДня(ТекДата + 86400);
	КонецЦикла;

// Спозиционируемся в списке на заданную дату
//-------------------------------------------------------------------------------------------------
	Если (ЗначениеЗаполнено(ДатаПозиционирования)) Тогда
		НайденныеСтроки = ЭтаФорма.Список.НайтиСтроки(Новый Структура("Дата",НачалоДня(ДатаПозиционирования)));

		Если (НайденныеСтроки.Количество() > 0) Тогда
			ИдентификаторСтроки = НайденныеСтроки[0].ПолучитьИдентификатор();
			Элементы.Список.ТекущаяСтрока = ИдентификаторСтроки;
		КонецЕсли;
	КонецЕсли;
КонецПроцедуры

&НаКлиенте
Процедура СписокРежимОчистка(Элемент,СтандартнаяОбработка)

// Установим на выбранную дату режим работы в соответствии с графиком по-умолчанию
//-------------------------------------------------------------------------------------------------
	Если (Элементы.Список.ТекущиеДанные <> Неопределено) Тогда
		ТекДата = НачалоДня(Элементы.Список.ТекущиеДанные.Дата);
		ОбщегоНазначения.РежимРаботыНаДатуУстановить(ТекДата,ЭтаФорма.ОбъектСсылка);
		СписокСформировать(ТекДата);
	КонецЕсли;

	СтандартнаяОбработка = Ложь;
КонецПроцедуры

&НаКлиенте
Процедура СписокПриИзменении(Элемент)

// Установим на выбранную дату выбранный режим работы
//-------------------------------------------------------------------------------------------------
	Если (Элементы.Список.ТекущиеДанные <> Неопределено) Тогда
		СтрПараметры = Новый Структура;
		СтрПараметры.Вставить("Режим",Элементы.Список.ТекущиеДанные.Режим);
		СтрПараметры.Вставить("НачВремя",Элементы.Список.ТекущиеДанные.НачВремя);
		СтрПараметры.Вставить("КонВремя",Элементы.Список.ТекущиеДанные.КонВремя);
		СтрПараметры.Вставить("Локально",?(ЭтаФорма.ОтображатьТипВызова,Элементы.Список.ТекущиеДанные.Локально,Ложь));

		ТекДата = НачалоДня(Элементы.Список.ТекущиеДанные.Дата);
		ОбщегоНазначения.РежимРаботыНаДатуУстановить(ТекДата,ЭтаФорма.ОбъектСсылка,СтрПараметры);
		СписокСформировать(ТекДата);
	КонецЕсли;
КонецПроцедуры
