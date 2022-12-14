&НаСервере
Процедура ПриСозданииНаСервере(Отказ,СтандартнаяОбработка)

// Сформируем сведения о ролях которыми наделен пользователь
//-------------------------------------------------------------------------------------------------
	Если (ЗначениеЗаполнено(Объект.УчетнаяЗаписьИБ)) Тогда
		ПолСсылка = ПользователиИнформационнойБазы.НайтиПоИмени(СокрЛП(Объект.УчетнаяЗаписьИБ));

		Если (ПолСсылка <> Неопределено) Тогда
			Для Каждого ТекСтрока Из ПолСсылка.Роли Цикл
				ЭтаФорма.СписокРолей = ЭтаФорма.СписокРолей + ?(ЗначениеЗаполнено(ЭтаФорма.СписокРолей),", ","");
				ЭтаФорма.СписокРолей = ЭтаФорма.СписокРолей + СокрЛП(ТекСтрока.Имя);
			КонецЦикла;
		КонецЕсли;
	КонецЕсли;

// Если пользователь является сотрудником контакт-центра, то скроем элемент "Подразделения",
// т.к. иерархия доступных подразделений определяется набором прав контакт-центра
//-------------------------------------------------------------------------------------------------
	Если (ЗначениеЗаполнено(Объект.Ссылка)) Тогда
		КЦСсылка = ЗначенияСервера.ПолучитьКонтактЦентр(Объект.Ссылка);

		Если (ЗначениеЗаполнено(КЦСсылка)) Тогда
			Темп = "Текущий пользователь является сотрудником контакт-центра [" + СокрЛП(КЦСсылка) + "], ";
			Темп = Темп + "поэтому список доступных подразделений задается исходя из настроек контакт-центра";
			Элементы.НадписьПодразделения.Заголовок = СокрЛП(Темп);
			Элементы.Подразделения.Видимость = Ложь;
		КонецЕсли;
	КонецЕсли;
КонецПроцедуры

&НаКлиенте
Процедура ПриОткрытии(Отказ)
	ОбновлениеОтображения();
КонецПроцедуры

&НаКлиенте
Процедура ОбновлениеОтображения(Элемент = Неопределено)

// Видимость кнопки активации пользователя и доступность формы для редактирования
//-------------------------------------------------------------------------------------------------
	Доступно = ЗначениеЗаполнено(Объект.Ссылка);
	Доступно = Доступно И (Объект.Активность = Ложь);
	Элементы.Активировать.Видимость = Доступно;
	ЭтаФорма.ТолькоПросмотр = Доступно;

// Отображение элемента "АутентификацияПараметр"
//-------------------------------------------------------------------------------------------------
	Если (Объект.АутентификацияСтандартная = Истина) Тогда
		Элементы.АутентификацияПараметр.РедактированиеТекста = Истина;
		Элементы.АутентификацияПараметр.РежимПароля = Истина;
		Элементы.АутентификацияПараметр.КнопкаВыбора = Ложь;
		Элементы.АутентификацияПараметр.Заголовок = "Пароль";
	Иначе
		Элементы.АутентификацияПараметр.Заголовок = "Учетная запись";
		Элементы.АутентификацияПараметр.РедактированиеТекста = Ложь;
		Элементы.АутентификацияПараметр.КнопкаВыбора = Истина;
		Элементы.АутентификацияПараметр.РежимПароля = Ложь;
	КонецЕсли;
КонецПроцедуры

&НаСервере
Процедура ПередЗаписьюНаСервере(Отказ,ТекущийОбъект,ПараметрыЗаписи)
	ТекущийОбъект.ДополнительныеСвойства.Вставить("Роли",ЭтаФорма.СписокРолей);
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ОбработкаВыбора(ВыбранноеЗначение,ИсточникВыбора)

// Выполним добавление выбранного элемента
//-------------------------------------------------------------------------------------------------
	Результат = ОбработкаВыбораПредприятие(ВыбранноеЗначение);

	Если (ЗначениеЗаполнено(Результат)) Тогда
		Предупреждение(Результат);
	КонецЕсли;
КонецПроцедуры

&НаСервере
Функция ОбработкаВыбораПредприятие(ВыбранноеЗначение)

// Сначала проверим не дублируется ли выбранное значение
//-------------------------------------------------------------------------------------------------
	Отбор = Новый Структура("Подразделение",ВыбранноеЗначение);
	НайденныеСтроки = Объект.Подразделения.НайтиСтроки(Отбор);

	Если (НайденныеСтроки.Количество() > 0) Тогда
		Возврат ("Выбранное подразделение уже присутствует в списке доступных");
	КонецЕсли;

// Выбранный элемент не дублируется явно
// Однако выбранный элемент может входить в иерархию другого присутствующего в списке элемента
//-------------------------------------------------------------------------------------------------
	Для Каждого ТекСтрока Из Объект.Подразделения Цикл
		Если (ВыбранноеЗначение.ПринадлежитЭлементу(ТекСтрока.Подразделение)) Тогда
			ТекстСообщения = "Выбранное подразделение находится в группе [" + СокрЛП(ТекСтрока.Подразделение);
			ТекстСообщения = ТекстСообщения + "], к которой у пользователя уже имеется доступ";
			Возврат (ТекстСообщения);
		КонецЕсли;
	КонецЦикла;

// Выбранный элемент не входит ни в какую присутствующую в списке иерархию
// Однако выбранный элемент может сам являться суперэлементом для каких-либо элементов списка
// Получим все элементы из ТЧ "Подразделения", которые входят в иерархию выбранного элемента
//-------------------------------------------------------------------------------------------------
	МассивУдаления = Новый Массив;
	ТекстУдаления = "";
	Ответ = "";

	Для Каждого ТекСтрока Из Объект.Подразделения Цикл
		Если (ТекСтрока.Подразделение.ПринадлежитЭлементу(ВыбранноеЗначение)) Тогда
			ТекстУдаления = ТекстУдаления + ?(ЗначениеЗаполнено(ТекстУдаления),Символы.ПС,"");
			ТекстУдаления = ТекстУдаления + СокрЛП(ТекСтрока.Подразделение.НаименованиеПолное);
			МассивУдаления.Добавить(ТекСтрока);
		КонецЕсли;
	КонецЦикла;

// Если в МассивеУдаления есть элементы, значит они входят в иерархию выбранного подразделения
// Эти элементы необходимо удалить. Известим об этом пользователя
//-------------------------------------------------------------------------------------------------
	Если (МассивУдаления.Количество() > 0) Тогда
		Для Каждого ТекСтрока Из МассивУдаления Цикл
			Объект.Подразделения.Удалить(ТекСтрока);
		КонецЦикла;

		Ответ = "Следующие подразделения были удалены из списка доступных, т.к. ";
		Ответ = Ответ + "выбранный элемент является вышестоящим для них:";
		Ответ = Ответ + Символы.ПС + СокрЛП(ТекстУдаления);
	КонецЕсли;

// Все проверки пройдены успешно
//-------------------------------------------------------------------------------------------------
	НовСтрока = Объект.Подразделения.Добавить();
	НовСтрока.Подразделение = ВыбранноеЗначение;
	ЭтаФорма.Модифицированность = Истина;
	Возврат (Ответ);
КонецФункции

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура Активировать(Команда)

// Выполним активацию объекта
//-------------------------------------------------------------------------------------------------
	Объект.Активность = Истина;
	ОбновлениеОтображения();
КонецПроцедуры

&НаКлиенте
Процедура СписокРолейНачалоВыбора(Элемент,ДанныеВыбора,СтандартнаяОбработка)

// Вызовем форму для редактирования набора ролей пользователя
//-------------------------------------------------------------------------------------------------
	СтрПараметры = Новый Структура("СписокРолей",ВРег(СокрЛП(ЭтаФорма.СписокРолей)));
	Результат = ОткрытьФормуМодально("Справочник.Пользователи.Форма.КорректировкаРолей",СтрПараметры);
	СтандартнаяОбработка = Ложь;

	Если (Результат <> Неопределено) Тогда
		ЭтаФорма.СписокРолей = СокрЛП(Результат);
	КонецЕсли;
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ПодразделенияПередНачаломДобавления(Элемент,Отказ,Копирование,Родитель,Группа,Параметр)

// Откроем форму для подбора подразделений
//-------------------------------------------------------------------------------------------------
	СтрПараметры = Новый Структура("ЗакрыватьПриВыборе",Ложь);
	ОткрытьФорму("Справочник.Предприятие.ФормаВыбораГруппы",СтрПараметры,ЭтаФорма);
	Отказ = Истина;
КонецПроцедуры

&НаКлиенте
Процедура АутентификацияПараметрНачалоВыбора(Элемент,ДанныеВыбора,СтандартнаяОбработка)

// Если процедура вызвана, значит текущий тип аутентификации - доменная
//-------------------------------------------------------------------------------------------------
	Результат = ОткрытьФормуМодально("Справочник.Пользователи.Форма.УчетнаяЗаписьДомена");
	Объект.АутентификацияПараметр = ?(Результат = Неопределено,Объект.АутентификацияПараметр,Результат);
	ОбновлениеОтображения();

// Если тип аутентификации - доменный и доменная учетная запись выбрана, то попытаемся получить
// имя пользователя по выбранной учетной записи (пока что только для домена MAIN.LUIDORAUTO.RU)
//-------------------------------------------------------------------------------------------------
	Доступно = (Объект.АутентификацияСтандартная = Ложь);
	Доступно = Доступно И (НЕ ЗначениеЗаполнено(Объект.Наименование));
	Доступно = Доступно И ЗначениеЗаполнено(Объект.АутентификацияПараметр);

	Если (Доступно = Истина) Тогда
		ИмяПользователяПолучитьНаСервере();
	КонецЕсли;
КонецПроцедуры

&НаСервере
Процедура ИмяПользователяПолучитьНаСервере()

// Получим объект LDAP
//-------------------------------------------------------------------------------------------------
	УчетнаяЗапись = Конвертация.СловоПолучить(Объект.АутентификацияПараметр,2,"\");
	ДомОбъект = ОбъектыДомена.ПользовательПолучитьПоУчетнойЗаписи(УчетнаяЗапись);

	Если (ТипЗнч(ДомОбъект) = Тип("COMОбъект")) Тогда
		Объект.Наименование = СокрЛП(ДомОбъект.DisplayName);
	КонецЕсли;
КонецПроцедуры
